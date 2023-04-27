# Below are in built import
from datetime import datetime as dt, timezone, timedelta as td

# Below are installed import
from flask import (
    render_template,
    request,
    session,
    send_from_directory,
    redirect,
    url_for,
)

# Below are custom imports
from app import app, utils
from app.auth import auth_required, client_required, auth_login
from app.models import PBIConfig, User, db
from app.powerbi.services.pbiembedservice import PBIService


@app.route("/")
@auth_required()
@client_required()
def index():
    return render_template(
        "index.html",
        isAdmin=session["admin"],
        client=session["current_client"],
        user=session["name"],
        user_id=session["personId"],
        ANsid=session["ANsid"],
    )


@auth_required()
@client_required()
@app.errorhandler(404)
def page_not_found(e):
    return render_template("page-not-found.html"), 404


@app.route("/login")
def login_form():
    # Get the current client first from query params (in url) and second from session
    current_client = request.args.get("clientid", session.get("current_client"))
    project_key = app.config.get("SSO_PROJECT_NAME")
    url_to_redirect_after_login = app.config.get("BASE_URL")
    # return redirect(
    #     f"https://devomni.annalect.com/extsso?resourcekey={project_key}&redirecturl={url_to_redirect_after_login}"
    # )
    return render_template(
        "login.html",
        client=current_client or "",
    )


@app.route("/login", methods=["POST"])
def do_login():
    login = request.json["login"]
    password = request.json["password"]
    client_id = request.json.get("clientid", session.get("current_client"))

    resp = auth_login(login, password, client_id)
    if not resp["success"]:
        app.logger.error(f"SSO LOGIN FAILED for {login}")
        return resp, 400
    else:
        return resp


@app.route("/client")
@auth_required()
def client_form():
    session.pop("current_client", None)
    return redirect(url_for("login_form"))


@app.route("/")
# @app.route("/admin")
@app.route("/reports")
@app.route("/dashboards")
@app.route("/reports/create")
@app.route("/reports/<id>/edit")
@app.route("/reports/<reportId>/view")
@app.route("/reports/<cloneRptId>/clone")
@app.route("/reports/<rptId>/delete")
@app.route("/dashboards/<dbId>/view")
@app.route("/dashboards/<dashboardId>/edit")
@app.route("/dashboards/<dshId>/delete")
@auth_required()
def admin_form(id = 0, reportId=0, dbId=0, dashboardId=0, cloneRptId=0, dshId=0, rptId=0):
    if session is None:
        return redirect(url_for("login_form"))

    return render_template(
        "index.html",
        isAdmin=session["admin"],
        client=session["current_client"],
        user=session["name"],
        user_id=session["personId"],
        ANsid=session["ANsid"],
    )

def get_all_clients():
    all_clients = [  # TODO: get this programatically
        {"id": "0C6CA90E-7687-11E9-8FA7-0A099936D88A", "name": "Army US"},
        {"id": "1996DB9E-DF97-11E4-AD98-121CF53DFF64", "name": "Cigna"},
        {"id": "87AC8A3B-F0D9-4CAC-B0BE-073378B25ECD", "name": "Pepsi"},
        {"id": "C7134162-8247-4202-9FCF-513F9FACAA45", "name": "SC Johnson"},
        {"id": "CDB03C20-A6C6-11E8-93EE-120A18B01F92", "name": "Beiersdorf APAC"},
        {"id": "DD787D18-BDD0-11E8-8505-126824A9F6C8", "name": "Infiniti US"},
        {"id": "FB34F1C5-D737-4003-AB68-975C9FB59C6E", "name": "Bacardi US"},
        {"id": "449203C6-7ED3-11E8-8B6B-0A35455287AC", "name": "Omni Demo US"},
    ]
    return all_clients


@app.route("/api/client")
def get_client_info():
    return {"clients": get_all_clients(), "current": session.get("current_client")}


@app.route("/report-templates/<file>")
@auth_required(allowed=["token"])
def get_report_template_jinja(file):
    return send_from_directory("static/build/report-templates", file)


@app.route("/users")
@auth_required()
def list_all_users():
    users = User.query.first()

    return {"success": True, "users": users}


@app.route("/api/powerbi/reports")
@auth_required(json=True)
def get_powerbi_reports():
    return {"reports": app.config["REPORTS"], "success": True}


@app.route("/api/powerbi/embed", methods=["GET"])
@auth_required(json=True)
@client_required(json=True)
def get_embed_info():
    from .powerbi.utils import Utils
    from .powerbi.services.pbiembedservice import PbiEmbedService

    """Returns report embed configuration"""
    print("v1")
    config_result = Utils.check_config(app)
    if config_result is not None:
        return {"success": False, "error": config_result}, 400

    try:
        username = session["current_client"]
        roles = ["Admin"] if session["admin"] else ["Client"]
        report_ids = list(map(lambda report: report["id"], app.config["REPORTS"]))

        embed_info = PbiEmbedService().get_embed_params_for_multiple_reports(
            app.config["WORKSPACE_ID"], report_ids, username, roles
        )
        response = embed_info.__dict__
        response["success"] = True
        return response
    except Exception as ex:
        app.logger.exception("Failed to get embed token")
        return {"success": False, "error": str(ex)}, 400


@app.route("/api/v1/powerbi/embed", methods=["GET"])
@auth_required(json=True)
@client_required(json=True)
def get_embed_info_v2():
    """
    This api will return embed token for all standard dashboards.
    NOTE: This considers that all standard dashboards are using same service principal.
    """
    from .powerbi.utils import Utils
    from .powerbi.services.pbiembedservice import PbiEmbedService

    print("v2")
    """Returns report embed configuration"""
    target_workspace_ids = []
    report_details = []
    config_result = Utils.check_config(app)
    if config_result is not None:
        return {"success": False, "error": config_result}, 400
    pbi_configs = PBIConfig.query.filter(PBIConfig.is_custom == False).all()
    for pbi_config in pbi_configs:
        target_workspace_ids.append(pbi_config.pbi_workspace_id.upper())

        report_details.append(
            {
                "name": pbi_config.pbi_report_name,
                "identity": pbi_config.pbi_identity_required,
            }
        )
        pbi_credential_id = pbi_config.pbi_credential_id
    try:
        print("session", session)
        username = session["current_client"]
        print("username", username)
        roles = ["Admin"] if session["admin"] else ["Client"]
        print("roles", roles)
        target_workspace_ids = list(set(target_workspace_ids))
        embed_info = (
            PbiEmbedService().get_embed_params_for_multiple_reports_multiple_workspaces(
                target_workspace_ids, report_details, username, roles, pbi_credential_id
            )
        )
        response = embed_info.__dict__
        response["success"] = True
        return response
    except Exception as ex:
        app.logger.exception("Failed to get embed token")
        return {"success": False, "error": str(ex)}, 400


@app.route("/api/powerbi/listvalues", methods=["POST"])
@auth_required(json=True)
def list_powerbi_values():
    import requests
    import json

    # Default to using the first report as the source (for now?)
    report_id = request.json.get("report_id", app.config["REPORTS"][0]["id"])
    embed_token = request.json["embed_token"]
    table_name = request.json["table_name"]
    column_name = request.json["column_name"]
    search_string = request.json.get("search_string", None)

    # Mystery value we get by looking at xhr POST (XXX)
    model_id = app.config["MODEL_ID"]

    # This url might break one day (XXX)
    url = "https://wabi-us-north-central-b-redirect.analysis.windows.net/explore/querydata?synchronous=true"
    where_filter = (
        {}
        if search_string is None
        else {
            "Where": [
                {
                    "Condition": {
                        "Contains": {
                            "Left": {
                                "Column": {
                                    "Expression": {"SourceRef": {"Source": "c"}},
                                    "Property": column_name,
                                }
                            },
                            "Right": {
                                "Literal": {
                                    "Value": f"""'{search_string.replace("'","''")}'"""
                                }
                            },
                        }
                    },
                    "Annotations": {"PowerBI.MParameterBehavior": 1},
                }
            ]
        }
    )

    data = json.dumps(
        {
            "version": "1.0.0",
            "queries": [
                {
                    "Query": {
                        "Commands": [
                            {
                                "SemanticQueryDataShapeCommand": {
                                    "Query": {
                                        "Version": 2,
                                        "Select": [
                                            {
                                                "Column": {
                                                    "Expression": {
                                                        "SourceRef": {"Source": "c"}
                                                    },
                                                    "Property": column_name,
                                                },
                                                "Name": f"{table_name}.{column_name}",
                                            }
                                        ],
                                        "From": [
                                            {
                                                "Name": "c",
                                                "Entity": table_name,
                                                "Type": 0,
                                            }
                                        ],
                                        **where_filter,
                                    },
                                    "Binding": {
                                        "Primary": {
                                            "Groupings": [{"Projections": [0]}]
                                        },
                                        "DataReduction": {
                                            "DataVolume": 3,
                                            "Primary": {"Window": {}},
                                        },
                                        "IncludeEmptyGroups": True,
                                        "Version": 1,
                                    },
                                    "ExecutionMetricsKind": 1,
                                }
                            }
                        ]
                    },
                    "QueryId": "",
                    "ApplicationContext": {
                        "DatasetId": app.config["DATASET_ID"],
                        "Sources": [{"ReportId": report_id}],
                    },
                }
            ],
            "cancelQueries": [],
            "modelId": model_id,
            "userPreferredLocale": "en-US",
        }
    )
    headers = {
        "authorization": f"EmbedToken {embed_token}",
        "content-type": "application/json",
    }

    try:
        r = requests.post(url, data=data, headers=headers)
        r.encoding = "utf-8-sig"
        resp = json.loads(r.text)
        is_complete = resp["results"][0]["result"]["data"]["dsr"]["DS"][0]["IC"]

        values = list(
            map(
                lambda x: x["G0"],
                resp["results"][0]["result"]["data"]["dsr"]["DS"][0]["PH"][0]["DM0"],
            )
        )
        return {"success": True, "values": values, "complete": is_complete}
    except Exception as e:
        app.logger.info(r)
        app.logger.info(r.text)
        app.logger.exception("Failed to query powerbi for values")
        return {"success": False, "error": str(e)}, 400


def get_pbi_service_instance(pbi_credential_id=None):
    access_token_details = utils.get_pbi_access_token_with_expiry_from_header()
    pbi_credential_id = pbi_credential_id or request.args.get("pbi_credential_id")
    if access_token_details["access_token"] or pbi_credential_id:

        pbi_service = PBIService(
            access_token=access_token_details["access_token"],
            pbi_credential_id=pbi_credential_id,
            expires_at=access_token_details["expires_at"],
        )
        return pbi_service
    else:
        raise Exception("Access token or pbi_credential_id required!")


@app.route("/api/v1/powerbi/workspaces", methods=["GET"])
@auth_required(json=True)
def get_pbi_workspace():
    """
    Gets workspace details from Power BI.
    NOTE: Use either access token or pbi_credential_id
    headers:
        pbi_access_token (str, optional): access token.
    request args:
        pbi_credential_id (uuid, optional): pbi credential id to create access token
    """
    pbi_service = get_pbi_service_instance()
    try:
        workspace_list = pbi_service.get_pbi_workspaces()
    except Exception as e:
        return {"success": False, "error": str(e)}, 400
    return {"success": True, "workspcaces": workspace_list}


@app.route("/api/v1/powerbi/reports/<pbi_report_id>", methods=["GET"])
@app.route("/api/v1/powerbi/reports", methods=["GET"])
@auth_required(json=True)
def get_pbi_reports(pbi_workspace_id=None, pbi_report_id=None):
    """
    Gets report details from Power BI using workspace id.
    NOTE: Use either access token or pbi_credential_id
    headers:
        pbi_access_token (str, optional): access token.
    request args:
        pbi_credential_id (uuid, optional): pbi credential id to create access token
        pbi_workspace_id (uuid): Power BI workspcae id
    request path:
        pbi_report_id (uuid, optional): Power BI report id to get specfic report
    """
    pbi_workspace_id = pbi_workspace_id or request.args.get("pbi_workspace_id")
    pbi_service = get_pbi_service_instance()
    try:
        report_list = pbi_service.get_pbi_reports(
            pbi_workspace_id, report_id=pbi_report_id
        )
    except Exception as e:
        return {"success": False, "error": str(e)}, 400
    return {"success": True, "reports": report_list}


@app.route("/api/v1/powerbi/pages/<pbi_page_id>", methods=["GET"])
@app.route("/api/v1/powerbi/pages", methods=["GET"])
@auth_required(json=True)
def get_pbi_pages(pbi_workspace_id=None, pbi_report_id=None, pbi_page_id=None):
    """
    Gets pages from Power BI using workspace id and report id.
    NOTE: Use either access token or pbi_credential_id
    headers:
        access_token (str, optional): access token.
    request args:
        pbi_credential_id (uuid, optional): pbi credential id to create access token
        pbi_workspace_id (uuid): Power BI workspcae id
        pbi_report_id (uuid): Power BI report id
    """
    pbi_workspace_id = pbi_workspace_id or request.args.get("pbi_workspace_id")
    pbi_report_id = pbi_report_id or request.args.get("pbi_report_id")
    pbi_service = get_pbi_service_instance()
    try:
        page_list = pbi_service.get_pbi_pages(
            pbi_workspace_id, pbi_report_id, page_id=pbi_page_id
        )
    except Exception as e:
        return {"success": False, "error": str(e)}, 400
    return {"success": True, "pages": page_list}


@app.route("/api/v1/powerbi/access-token", methods=["GET"])
@auth_required(json=True)
def get_access_token_v1():
    """
    This api will return access token for specific credential_id.
    """

    from .powerbi.services.pbiembedservice import PBIService

    now = dt.now(timezone.utc)
    pbi_credential_id = request.args.get("pbi_credential_id")
    pbi_service = PBIService(pbi_credential_id=pbi_credential_id)
    access_token = pbi_service.get_access_token()
    expires_at = now + td(hours=1)
    return {
        "success": True,
        "pbi_credential_id": pbi_credential_id,
        "access_token": access_token,
        "expires_at": expires_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


@app.route("/api/v1/powerbi/embed-token", methods=["GET"])
@auth_required(json=True)
def get_embed_token_v1(auth_type=None):
    """
    Generates embed token for specific config.
    """
    from .powerbi.services.pbiembedservice import PbiEmbedService

    pbi_config_id = request.args.get("pbi_config_id")
    client_id = utils.get_client_id(auth_type=auth_type)
    pbi_config = PBIConfig.query.filter_by(id=pbi_config_id).first()
    db.session.close()  # Need to call this as while updating pbiconfig same session should not get used.
    if not pbi_config:
        return {
            "success": False,
            "error": f"pbi config not found: {pbi_config_id}",
        }, 400
    pbi_service = get_pbi_service_instance(pbi_config.pbi_credential_id)
    headers = pbi_service.get_headers()

    required_keys = [
        "pbi_workspace_id",
        "pbi_report_id",
        "pbi_report_name",
        "pbi_dataset_id",
        "pbi_embed_url",
        "pbi_identity_required",
    ]
    if not all(i in pbi_config.params for i in required_keys):
        return {
            "success": False,
            "error": "Pbi config does not have required params",
        }, 400
    username = client_id
    roles = ["Admin"] if session["admin"] else ["Client"]
    try:
        embed_info = PbiEmbedService().get_embed_params_for_single_report(
            params=pbi_config.params,
            username=username,
            roles=roles,
            headers=headers,
            pbi_config_id=pbi_config_id,
        )
        response = embed_info.__dict__
        response["success"] = True
    except Exception as ex:
        app.logger.exception("Failed to get embed token")
        return {"success": False, "error": str(ex)}, 400
    return response


# Note
# written access token code.
# left this branch when was checking if embed url changes.
# Need to write embed token code and modify single report call to minimise the calls.
# update post call of config to use report id and dataset id and embed url
