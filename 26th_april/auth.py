from app import app, utils
from functools import wraps, update_wrapper
from flask import request, session, redirect, url_for
import requests
import time
from inspect import signature
from dataclasses import dataclass, field, asdict

## create a class for authetication check on valid session
## what kind of authentication was performed, 
## whether the user needs to re-login, and whether the user needs to be redirected somewhere.

@dataclass
class AuthInfo:
    success: bool = False
    error: str = None
    auth_type: str = "session"
    relogin: bool = False
    redirect: str = None
    redirect_args: dict = field(default_factory=dict)

## created a class for Under Authentication 
## a data class that represents information about a user
## including their session ID, name, email, client, and profile data

@dataclass
class UserInfo:
    sid: str
    name: str = ""
    email: str = ""
    personId: str = ""
    admin: bool = False
    clients: list = field(repr=False, default_factory=list)
    client: str = None
    profile: dict = field(default_factory=dict)
    login_success: bool = False
    error: str = None

### admin --> it indicates that whether the user is administrator or not.
### client --> it giving options on what clients they have to access

    def __post_init__(self):
        profile_found = self.get_profile()
        if profile_found:
            self.process_profile()

        if self.client is not None:
            self.client = self.client.upper()
            self.client_name = [
                client_data["orgName"]
                for client_data in self.profile.get("clients")
                if self.client.upper() == client_data["clientId"].upper()
            ][0]

        if self.admin is True or len(self.clients) > 0:
            if (
                self.client is not None
                and self.client not in self.clients
                and not self.admin
            ):
                app.logger.error(
                    f"User {self.name} blocked from accessing client {self.client}"
                )
                self.error = "User not permissioned to client"
                session.pop("current_client", None)
                return

            self.login_success = True
            self.set_session()
        else:
            project = app.config["SSO_PROJECT_NAME"]
            app.logger.error(f"Login failed: user does not have access to {project}")

    def get_profile(self):
        prof = requests.get(app.config["SSO_PROFILE_URL"], cookies={"ANsid": self.sid})
        if prof.status_code == 200:
            self.profile = prof.json()
            self.name = self.profile.get("fullName")
            self.email = self.profile.get("email")
            self.personId = self.profile.get("personId")
        else:
            app.logger.error(
                f"failed to obtain profile ({app.config['SSO_PROFILE_URL']})"
            )
            return False
        return True

## the above def function that sends an HTTP [GET] request to the server to gain the user's data, giving their session ID.
## it will return true if the request was successful, orelse it will return False.


    def process_profile(self):
        for project in self.profile.get("projects"):
            type_key = project.get("typeKey")

            if type_key != app.config["SSO_PROJECT_NAME"]:
                continue

            user_roles = project.get("userRoles", [])
            if "administrator" in user_roles:
                app.logger.info(f"Login successful for admin {self.name} {self.email}")
                self.admin = True
            elif "viewer" in user_roles:
                app.logger.info(f"Login successful for viewer {self.name} {self.email}")
                clients = map(lambda c: c["clientId"], self.profile.get("clients", []))
                self.clients = list(map(lambda c: c.upper(), clients))

## it proccessing the users profile to identify whether they are an admin or viewser, and list of client they have access to


    def set_session(self):
        session["ANsid"] = self.sid
        session["expires"] = time.time() + app.config["AUTH_SESSION_EXPIRES"]
        session["admin"] = self.admin
        session["current_client"] = self.client
        session["name"] = self.name
        session["email"] = self.email
        session["personId"] = self.personId
        session["client_name"] = self.client_name

        from app.models import User

        User.save_user_info(self.name, self.email, self.personId)
        role = "Admin" if self.admin else "Viewer"
        client = f"(client: {session['current_client']})"
        app.logger.info(
            f"Session created for {self.name} {self.email}: {role} {client}"
        )


def invalidate_session():
    # Remove everything from session except "current_client"
    session.pop("ANsid", None)
    session.pop("expires", None)
    session.pop("admin", None)
    session.pop("name", None)
    session.pop("email", None)
    session.pop("personId", None)


def check_annalect_session_id():
    """Test if we already have a session cookie for the user"""
    info = AuthInfo()
    now = time.time()
    expires = session.get("expires", 0)

    if "ANsid" not in session:
        invalidate_session()
        info.error = "No session found"
    elif now > expires:
        invalidate_session()
        info.error = "Session expired"
    else:
        info.success = True
    return info


def check_api_token():
    """Test if Api-Token is in HTTP headers (for programatic access)"""
    info = AuthInfo(auth_type="token")
    is_configured = "AUTH_SECRET_ID" in app.config
    has_token = "Api-Token" in request.headers

    if is_configured and has_token:
        import pylect_infra as pinfra

        token = request.headers.get("Api-Token")
        try:
            if app.config["FLASK_ENV_EDITABLE"] == "local":
                secret = "annalect"
            else:
                secret = pinfra.secrets.get_value(app.config["AUTH_SECRET_ID"])
        except Exception:
            app.logger.exception(
                f"Failed to get secret: {app.config['AUTH_SECRET_ID']}"
            )
            info.error = f"Failed to retrieve secret from secrets manager {app.config['AUTH_SECRET_ID']}"
            return info

        if token == secret:
            info.success = True
        else:
            info.error = "Invalid secret api token"

    return info

## this above function that checks whether the user have a valid token in their header section.

def check_session_from_omni():
    """Test if ANsid is passed as a query parameter (this is done by omni)"""
    info = AuthInfo()
    args = request.args.to_dict()
    sid = args.pop("ANsid", None)
    client = args.pop("clientid", None)
    omni = args.pop("omni", None)
    if sid:
        user = UserInfo(sid=sid, client=client)
        if user.login_success:
            info.success = True
            info.redirect = request.endpoint  # Redirect to url without query params
            info.redirect_args = args
        else:
            info.error = "Invalid sid from omni post"
    return info


def auth_checks():
    """Try the three possible authentication styles"""
    info = check_api_token()
    if info.success or info.error is not None:
        return info

    info = check_session_from_omni()
    if info.success or info.error is not None:
        return info

    return check_annalect_session_id()


def client_required(json=False):
    """
    Decorator for flask view functions which require a client to be selected in the
    current session.
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if "current_client" in session and session["current_client"] is not None:
                return f(*args, **kwargs)

            error = "No client selected in session"
            app.logger.error(error)
            if json:
                return {"success": False, "error": error}, 400
            else:
                resp = redirect(url_for("login_form", redirect=request.full_path))
                return resp

        return update_wrapper(decorated_function, f)

    return decorator


def only_admin_route(json=True):
    "Allows only admin to access the route."

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if (
                kwargs.get("auth_type") == "session" and session.get("admin")
            ) or kwargs.get("auth_type") == "token":
                # if kwargs.get("auth_type") == "token":
                return f(*args, **kwargs)

            error = "Admin previliage required to access this url."
            app.logger.error(error)
            if json:
                return {"success": False, "error": error}, 400
            else:
                resp = redirect(url_for("login_form", redirect=request.full_path))
            return resp

        return update_wrapper(decorated_function, f)

    return decorator


def get_jwt_token():
    """
    Decorator to get jwt token from omni shared object.
    If jwt is needed by api token then pass "Api-Token" in header with secret value.
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            env = utils.get_url_env()
            if env != "local":
                if request.headers.get("Api-Token"):
                    payload = {"token": request.headers.get("Api-Token")}
                    jwt_url = (
                        f"https://{env}shared-objects.api.annalect.com/token/orad/"
                    )
                elif session.get("ANsid"):
                    ans_id = session["ANsid"]
                    payload = {
                        "client_guid": session["current_client"],
                        "sso_env": env,  # this will work as "" or "prod" for prod
                        "omni_admin": 1,
                    }
                    jwt_url = f"https://{env}shared-objects.api.annalect.com/token/ansid/{ans_id}"
                response = requests.post(jwt_url, json=payload)
                if response.ok:
                    # session["jwt_token"] = response.text
                    res_dict = {"jwt_token": response.text}
                    return f(*args, **kwargs, **res_dict)

                error = response.text
                app.logger.error(error)
                return {"success": False, "error": error}, response.status_code
            else:
                return {"success": False, "error": f"Not in correct env: {env}"}

        return update_wrapper(decorated_function, f)
        # session.pop("jwt_token")

    return decorator


def auth_required(json=False, allowed=["session", "token"]):
    """
    Decorator for flask view functions that will require authentication.
    If authentication fails, the user will be redirected to login.
    Three types of authentication exist:
        1. Login/Pass authentication (form submission)
        2. ANsid query param authentication (<url>?ANSid=...)
        3. Token authentication (in http header "Api-Token")
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            sesh = auth_checks()
            if sesh.success:
                if sesh.auth_type not in allowed:
                    if json:
                        return {"success": False, "error": "Auth-type not allowed"}, 400
                    else:
                        return "Auth-type not allowed", 400

                if sesh.redirect is not None:
                    return redirect(
                        url_for(sesh.redirect, **sesh.redirect_args, **kwargs), code=307
                    )

                more_kwargs = {}
                if "auth_type" in signature(f).parameters:
                    more_kwargs = {"auth_type": sesh.auth_type}

                return f(*args, **kwargs, **more_kwargs)

            app.logger.error(sesh.error)

            if json:
                sesh.relogin = True
                return asdict(sesh), 400
            if app.config.get("FLASK_ENV_EDITABLE") in ["local", "dev", "qa"]:
                project_key = app.config.get("SSO_PROJECT_NAME")
                url_to_redirect_after_login = app.config.get("BASE_URL")
                sso2_auth_url = app.config.get("SSO2_ACCESS_URL").format(
                    env=utils.get_url_env(local_as_dev=True),
                    project_key=project_key,
                    url_to_redirect_after_login=url_to_redirect_after_login,
                )
                return redirect(sso2_auth_url)
            else:
                resp = redirect(
                    url_for(
                        "login_form",
                        redirect=request.full_path,
                        clientid=request.args.get("clientid"),
                        admin=request.args.get("admin"),
                    )
                )
                return resp

        return update_wrapper(decorated_function, f)

    return decorator


def auth_login(login, password, client_id=None):
    """Login user with a login and password, and setup session"""
    response = requests.post(
        app.config["SSO_LOGIN_URL"] + login,
        data={"p": password},
        verify=False,
        timeout=30,
    )

    if response.status_code != 200:
        app.logger.info(
            f"Login failed ({response.status_code}): ({app.config['SSO_LOGIN_URL']})"
        )
        return {"success": False, "error": "Login Failed"}

    sso = response.json()
    code = sso.get("loginResponseCode")
    sid = sso.get("sid")
    app.logger.debug(f"SSO: {sso}")
    if code != "1" or sid is None:
        app.logger.info(
            f"Login failed: user/pass rejected ({app.config['SSO_LOGIN_URL']})"
        )
        return {"success": False, "error": "Login Failed"}

    user = UserInfo(sid=sid, client=client_id)
    userDetail = {
        "admin": user.admin,
        "client": user.client,
        "email": user.email,
        "login_success": user.login_success,
        "name": user.name,
        "clients": user.profile["clients"],
        "ANsid": user.sid,
    }
    if user.login_success:
        return {"success": userDetail}

    return {"success": False, "error": user.error or "Login Failed"}


def jsonify_exceptions():
    """Simple decorator to catch exceptions, log them, and return json error response"""

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                return f(*args, **kwargs)
            except Exception as e:
                app.logger.exception(e)
                return {"success": False, "error": str(e)}

        return update_wrapper(decorated_function, f)

    return decorator
