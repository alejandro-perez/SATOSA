"""
A Federated OpenID Connect frontend module for the satosa proxy
"""
import json
import logging

from fedoidc.provider import Provider
from fedoidc.signing_service import InternalSigningService
from fedoidc.test_utils import own_sign_keys, create_federation_entity
from fedoidc.utils import store_signed_jwks
from oic.oic.provider import RegistrationEndpoint
from oic.utils import shelve_wrapper
from oic.utils.authn.client import verify_client
from oic.utils.authz import AuthzHandling
from oic.utils.keyio import keyjar_init
from oic.utils.sdb import create_session_db
from oic.utils.userinfo import UserInfo
from oic.utils.userinfo.aa_info import AaUserInfo

from satosa.frontends.base import FrontendModule
from satosa.response import Response

logger = logging.getLogger(__name__)


class FedOpenIDConnectFrontend(FrontendModule):
    """
    A Federated OpenID Connect frontend module
    """

    def __init__(self, auth_req_callback_func, internal_attributes, conf, base_url, name):
        SIGKEY_NAME = 'sigkey.jwks'

        super().__init__(auth_req_callback_func, internal_attributes, base_url, name)
        self.config = conf
        _op = self._op_setup()
        sign_kj = own_sign_keys(SIGKEY_NAME, _op.baseurl, conf["SIG_DEF_KEYS"])
        store_signed_jwks(_op.keyjar, sign_kj, conf["SIGNED_JWKS_PATH"],
                          conf["SIGNED_JWKS_ALG"], iss=_op.baseurl)

        fed_ent = create_federation_entity(iss=_op.baseurl, ms_dir=conf["MS_DIR"],
                                           jwks_dir=conf["JWKS_DIR"],
                                           sup=conf["SUPERIOR"],
                                           fo_jwks=conf["FO_JWKS"],
                                           sig_keys=sign_kj,
                                           sig_def_keys=conf["SIG_DEF_KEYS"])
        fed_ent.signer.signing_service = InternalSigningService(_op.baseurl, sign_kj)
        _op.federation_entity = fed_ent
        fed_ent.httpcli = _op

        self.op = _op

    def _op_setup(self):
        response_types_supported = self.config["provider"].get("response_types_supported", ["id_token"])
        subject_types_supported = self.config["provider"].get("subject_types_supported", ["pairwise"])
        scopes_supported = self.config["provider"].get("scopes_supported", ["openid"])
        INSECURE = True
        CAPABILITIES = {
            "issuer": self.base_url,
            "response_types_supported": response_types_supported,
            "response_modes_supported": ["fragment", "query"],
            "subject_types_supported": subject_types_supported,
            "claim_types_supported": ["normal"],
            "claims_parameter_supported": True,
            "claims_supported": [attribute_map["openid"][0]
                                 for attribute_map in
                                 self.internal_attributes["attributes"].values()
                                 if "openid" in attribute_map],
            "request_parameter_supported": False,
            "request_uri_parameter_supported": False,
            "scopes_supported": scopes_supported
        }
        DEBUG = True

        # Client data base
        cdb = shelve_wrapper.open("client_db")
        _issuer = self.base_url
        if _issuer[-1] != '/':
            _issuer += '/'

        # dealing with authorization
        authz = AuthzHandling()

        kwargs = {}

        # Should I care about verifying the certificates used by other entities
        kwargs["verify_ssl"] = not INSECURE

        if CAPABILITIES:
            kwargs["capabilities"] = CAPABILITIES

        _sdb = create_session_db(_issuer, 'automover', '430X', {})
        _op = Provider(_issuer, _sdb, cdb, None, None,
                           authz, verify_client, self.config["SYM_KEY"], **kwargs)
        _op.baseurl = _issuer

        if self.config["USERINFO"] == "SIMPLE":
            # User info is a simple dictionary in this case statically defined in
            # the configuration file
            _op.userinfo = UserInfo(self.config["USERDB"])
        elif self.config["USERINFO"] == "SAML":
            _op.userinfo = UserInfo(self.config["SAML"])
        elif self.config["USERINFO"] == "AA":
            _op.userinfo = AaUserInfo(self.config["SP_CONFIG"], _issuer, self.config["SAML"])
        else:
            raise Exception("Unsupported userinfo source")

        try:
            _op.cookie_ttl = self.config["COOKIETTL"]
        except AttributeError:
            pass

        try:
            _op.cookie_name = self.config["COOKIENAME"]
        except AttributeError:
            pass

        _op.debug = DEBUG

        try:
            jwks = keyjar_init(_op, self.config["keys"], kid_template="op%d")
        except Exception as err:
            logger.error("Key setup failed: %s" % err)
            _op.key_setup("static", sig={"format": "jwk", "alg": "rsa"})
        else:
            f = open(self.config["JWKS_FILE_NAME"], "w")
            f.write(json.dumps(jwks))
            f.close()

            _op.jwks_uri = "%s%s" % (_op.baseurl, self.config["JWKS_FILE_NAME"])

            try:
                _op.signed_jwks_uri = "%s%s" % (_op.baseurl, self.config["SIGNED_JWKS_PATH"])
            except AttributeError:
                pass

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
        provider_config = ("^.well-known/openid-configuration$", self.provider_config)
        client_registration = ("^{}".format(RegistrationEndpoint.url),
                               self.handle_client_registration)
        url_map = [provider_config, client_registration]
        return url_map

    def provider_config(self, context):
        """
        Construct the provider configuration information (served at /.well-known/openid-configuration).
        :type context: satosa.context.Context
        :rtype: oic.utils.http_util.Response

        :param context: the current context
        :return: HTTP response to the client
        """
        return self.op.providerinfo_endpoint()

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

    def handle_backend_error(self, exception):
        pass

    def handle_authn_response(self, context, internal_resp):
        pass
