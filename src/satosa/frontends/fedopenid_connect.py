"""
A Federated OpenID Connect frontend module for the satosa proxy
"""
import json
import logging
from urllib.parse import urlencode

from fedoidc.provider import Provider
from fedoidc.signing_service import InternalSigningService
from fedoidc.test_utils import own_sign_keys, create_federation_entity
from fedoidc.utils import store_signed_jwks
from oic.oic import scope2claims
from oic.oic.provider import RegistrationEndpoint, AuthorizationEndpoint, TokenEndpoint, \
    UserinfoEndpoint
from oic.utils import shelve_wrapper
from oic.utils.authn.client import verify_client
from oic.utils.authz import AuthzHandling
from oic.utils.keyio import keyjar_init
from oic.utils.sdb import create_session_db, AuthnEvent
from oic.utils.userinfo import UserInfo
from oic.oic.message import AuthorizationRequest, AuthorizationErrorResponse

from satosa.frontends.base import FrontendModule
from satosa.internal_data import InternalRequest, UserIdHashType
from satosa.logging_util import satosa_logging
from satosa.response import Response, SeeOther

logger = logging.getLogger(__name__)


def oidc_subject_type_to_hash_type(subject_type):
    if subject_type == "public":
        return UserIdHashType.public
    return UserIdHashType.pairwise


class FedOpenIDConnectFrontend(FrontendModule):
    """
    A Federated OpenID Connect frontend module
    """

    def __init__(self, auth_req_callback_func, internal_attributes, conf, base_url, name):
        super().__init__(auth_req_callback_func, internal_attributes, base_url, name)
        self.config = conf
        self.user_db = {}

        _op = self._op_setup()
        fconf = conf["federation"]
        sign_kj = own_sign_keys(fconf["signing_keys"]["path"], _op.baseurl,
                                fconf["signing_keys"]["key_defs"])

        store_signed_jwks(_op.keyjar, sign_kj, fconf["signed_jwks"]["path"],
                          fconf["signed_jwks"]["sign_alg"], iss=_op.baseurl)

        fed_ent = create_federation_entity(iss=_op.baseurl, ms_dir=fconf["signed_ms"]["path"],
                                           jwks_dir=fconf["fo_keys"]["path"],
                                           sig_keys=sign_kj,
                                           sig_def_keys=fconf["signing_keys"]["key_defs"])
        fed_ent.signer.signing_service = InternalSigningService(_op.baseurl, sign_kj)
        _op.federation_entity = fed_ent
        fed_ent.httpcli = _op

        self.op = _op

    def _op_setup(self):
        self.capabilities = {
            "issuer": self.base_url,
            "response_types_supported": self.config["capabilities"].get("response_types_supported",
                                                                        ["id_token"]),
            "response_modes_supported": ["fragment", "query"],
            "subject_types_supported": self.config["capabilities"].get("subject_types_supported",
                                                                       ["pairwise"]),
            "claim_types_supported": ["normal"],
            "id_token_signing_alg_values_supported": ["none"],
            "claims_parameter_supported": True,
            "claims_supported": [attribute_map["openid"][0]
                                 for attribute_map in
                                 self.internal_attributes["attributes"].values()
                                 if "openid" in attribute_map],
            "request_parameter_supported": False,
            "request_uri_parameter_supported": False,
            "scopes_supported": self.config["capabilities"].get("scopes_supported", ["openid"])
        }
        # Client data base
        cdb = shelve_wrapper.open(self.config.get("client_db_path", "client_db"))
        _issuer = self.base_url
        if _issuer[-1] != '/':
            _issuer += '/'

        _sdb = create_session_db(_issuer, 'automover', '430X', {})

        kwargs = {"verify_ssl": self.config.get("VERIFY_SSL", True),
                  "capabilities": self.capabilities}
        _op = Provider(_issuer, _sdb, cdb, None, UserInfo(self.user_db), AuthzHandling(),
                       verify_client, self.config["SYM_KEY"], **kwargs)
        _op.cookie_ttl = 4 * 60  # 4 hours
        _op.cookie_name = 'fedoic_cookie'
        _op.debug = self.config.get("DEBUG", False)

        try:
            jwks = keyjar_init(_op, self.config["jwks"]["key_defs"], kid_template="op%d")
        except Exception as err:
            logger.error("Key setup failed: %s" % err)
            _op.key_setup("static", sig={"format": "jwk", "alg": "rsa"})
        else:
            f = open(self.config["jwks"]["path"], "w")
            f.write(json.dumps(jwks))
            f.close()

            _op.keyjar.verify_ssl = kwargs["verify_ssl"]

        for b in _op.keyjar[""]:
            logger.info("OC3 server keys: %s" % b)

        return _op

    def register_endpoints(self, backend_names):
        """
        See super class satosa.frontends.base.FrontendModule
        :type backend_names: list[str]
        :rtype: list[(str, ((satosa.context.Context, Any) -> satosa.response.Response, Any))]
        :raise ValueError: if more than one backend is configured
        """

        self.backendname = backend_names[0]
        provider_config = ("^.well-known/openid-configuration$", self.provider_config)
        client_registration = ("^{}/{}/{}".format(backend_names[0], self.name,
                                                  RegistrationEndpoint.url),
                               self.handle_client_registration)
        authorization = ("{}/{}/{}".format(backend_names[0], self.name, AuthorizationEndpoint.url),
                         self.handle_authn_request)
        token = ("{}/{}/{}".format(backend_names[0], self.name, TokenEndpoint.url),
                         self.token_endpoint)
        userinfo = ("{}/{}/{}".format(backend_names[0], self.name, UserinfoEndpoint.url),
                         self.userinfo_endpoint)

        jwks_uri = "{}/{}/jwks".format(self.backendname, self.name)
        jwks = (jwks_uri, self.jwks)
        self.op.jwks_uri = "{}/{}".format(self.base_url, jwks_uri)

        signed_jwks_uri = "{}/{}/signed_jwks".format(self.backendname, self.name)
        signed_jwks = (signed_jwks_uri, self.signed_jwks)
        self.op.signed_jwks_uri = "{}/{}".format(self.base_url, signed_jwks_uri)

        url_map = [provider_config, client_registration, authorization, token, userinfo, jwks,
                   signed_jwks]
        return url_map

    def token_endpoint(self, context):
        """
        Handle token requests (served at /token).
        :type context: satosa.context.Context
        :rtype: oic.utils.http_util.Response

        :param context: the current context
        :return: HTTP response to the client
        """
        req = urlencode(context.request)
        authn = context.request_authorization
        return self.op.token_endpoint(req, authn)

    def userinfo_endpoint(self, context):
        """
        Handle userinfo requests (served at /userinfo).
        :type context: satosa.context.Context
        :rtype: oic.utils.http_util.Response

        :param context: the current context
        :return: HTTP response to the client
        """
        req = urlencode(context.request)
        authn = context.request_authorization
        return self.op.userinfo_endpoint(req, authn=authn)

    def provider_config(self, context):
        """
        Construct the provider configuration information (served at /.well-known/openid-configuration).
        :type context: satosa.context.Context
        :rtype: oic.utils.http_util.Response

        :param context: the current context
        :return: HTTP response to the client
        """

        # Temporarily replacing OP's baseurl is the only way I figured out to add backend name
        # into the endpoint URLs
        backup = self.op.baseurl
        self.op.baseurl = '{}/{}/{}'.format(self.base_url, self.backendname, self.name)
        config = self.op.providerinfo_endpoint()
        self.op.baseurl = backup
        return config

    def handle_client_registration(self, context):
        """
        Handle the OIDC dynamic client registration.
        :type context: satosa.context.Context
        :rtype: oic.utils.http_util.Response

        :param context: the current context
        :return: HTTP response to the client
        """
        req = json.dumps(context.request)
        return self.op.registration_endpoint(req)

    def handle_authn_request(self, context):
        """
        Handle an authentication request and pass it on to the backend.
        :type context: satosa.context.Context
        :rtype: oic.utils.http_util.Response

        :param context: the current context
        :return: HTTP response to the client
        """
        request = urlencode(context.request)
        satosa_logging(logger, logging.DEBUG, "Authn req from client: {}".format(request),
                       context.state)
        context.state[self.name] = {"oidc_request": request}

        authn_req = AuthorizationRequest().deserialize(request)
        _cid = authn_req["client_id"]
        cinfo = self.op.cdb[str(_cid)]

        # If client keys were not stored already, store them
        if _cid not in self.op.keyjar.issuer_keys:
            if "jwks_uri" in cinfo:
                self.op.keyjar.issuer_keys[_cid] = []
                self.op.keyjar.add(_cid, cinfo["jwks_uri"])

        hash_type = oidc_subject_type_to_hash_type(cinfo.get("subject_type", "pairwise"))

        client_name = cinfo.get("client_name")
        requester_name = [{"lang": "en", "text": client_name}] if client_name else None

        internal_req = InternalRequest(hash_type, _cid, requester_name)
        internal_req.approved_attributes = self.converter.to_internal_filter(
            "openid", self._get_approved_attributes(authn_req))

        return self.auth_req_callback_func(context, internal_req)

    def handle_backend_error(self, exception):
        """
        See super class satosa.frontends.base.FrontendModule
        :type exception: satosa.exception.SATOSAError
        :rtype: oic.utils.http_util.Response
        """
        auth_req = AuthorizationRequest().deserialize(exception.state[self.name]["oidc_request"])
        # If the client sent us a state parameter, we should reflect it back according to the spec
        if 'state' in auth_req:
            error_resp = AuthorizationErrorResponse(error="access_denied",
                                                    error_description=exception.message,
                                                    state=auth_req['state'])
        else:
            error_resp = AuthorizationErrorResponse(error="access_denied",
                                                    error_description=exception.message)
        satosa_logging(logger, logging.DEBUG, exception.message, exception.state)
        use_fragment_encoding = (auth_req['response_type'] == ['code'])
        return SeeOther(error_resp.request(auth_req["redirect_uri"], use_fragment_encoding))

    def handle_authn_response(self, context, internal_resp):
        """
        See super class method satosa.frontends.base.FrontendModule#handle_authn_response
        :type context: satosa.context.Context
        :type internal_response: satosa.internal_data.InternalResponse
        :rtype oic.utils.http_util.Response
        """
        auth_req = AuthorizationRequest().deserialize(context.state[self.name]["oidc_request"])
        attributes = self.converter.from_internal("openid", internal_resp.attributes)
        self.user_db[internal_resp.user_id] = {k: v[0] for k, v in attributes.items()}

        _cid = auth_req["client_id"]
        cinfo = self.op.cdb[str(_cid)]

        logger.debug("- authenticated -")
        logger.debug("AREQ keys: %s", list(auth_req.keys()))

        sid = self.op.setup_session(auth_req, AuthnEvent(internal_resp.user_id, "salt"), cinfo)
        authnres = self.op.authz_part2(internal_resp.user_id, auth_req, sid)
        del context.state[self.name]
        return authnres

    def _get_approved_attributes(self, authn_req):
        provider_supported_claims = self.capabilities["claims_supported"]
        requested_claims = list(scope2claims(authn_req["scope"]).keys())
        if "claims" in authn_req:
            for k in ["id_token", "userinfo"]:
                if k in authn_req["claims"]:
                    requested_claims.extend(authn_req["claims"][k].keys())
        return set(provider_supported_claims).intersection(set(requested_claims))

    def jwks(self, context):
        """
        Construct the JWKS document (served at /jwks).
        :type context: satosa.context.Context
        :rtype: oic.utils.http_util.Response

        :param context: the current context
        :return: HTTP response to the client
        """
        jwks = ""
        with open(self.config["jwks"]["path"], "r") as f:
            jwks = f.read()
        return Response(jwks, content="application/json")

    def signed_jwks(self, context):
        """
        Construct the JWKS document (served at /signed_jwks).
        :type context: satosa.context.Context
        :rtype: oic.utils.http_util.Response

        :param context: the current context
        :return: HTTP response to the client
        """
        jwks = ""
        with open(self.config["federation"]["signed_jwks"]["path"], "r") as f:
            jwks = f.read()
        return Response(jwks, content="application/json")