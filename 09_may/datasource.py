#below are built-in imports
from datetime import  datetime as dt, timezone
import ast

#below are installed imports
from flask import Blueprint, request, session
from sqlalchemy.exc import IntegrityError

#below are custom imports
from app import app, utils, reportso
from app.models import DataSource, DataSourceField, db
from .auth import auth_required

datasource_api = Blueprint("datasource_api", __name__, url_prefix="/api/v1/ds")


"""APIs"""
## below code is for getting data from database

@datasource_api.route("/datasource", methods=["GET"])
@datasource_api.route("/<datasource_id>", methods=["GET"])
@auth_required(json=True)
def get_datasource(
     datasource_id=None,
     auth_type=None, 
):
     datasources = DataSource.query
     id = request.args.get("datasource_id")
     name = request.args.get("name")
     connection_details = request.args.get("connection")
     connection_type = request.args.get("connection_type")
     create_time = request.args.get("create_time")
     modify_time = request.args.get("modify_time")
     created_by = request.args.get("created_by")
     updated_by = request.args.get("updated_by")
     
     if datasource_id:
        datasource = DataSource.query.filter_by(id=datasource_id).first()






## below code is for inserting into the datasource table
## refer to dashboard file

@datasource_api.route("/datasource", methods=["POST"])
@auth_required(json=True)
def create_datasource(
    id = None,
    name = None,
    connection_details = None,
    connection_type = None,
    create_time = None,
    modify_time = None,
    created_by = None,
    updated_by = None,
):
    id = id or request.json.get("id")
    name = name or request.json.get("name")
    data = data or request.json.get("data")
    connecting_details = connection_details or request.json.get("connection_details")
    connecting_type = connection_type or request.json.get("connection_type")
    create_time = create_time or request.json.get("create_time")
    modify_time = modify_time or request.json.get("modify_time")
    created_by = created_by or request.json.get("created_by") 
    updated_by = updated_by or request.json.get("updated_by") 
    
    try:
        datasource = DataSource(
             id = id,
             name = name,
             data = data,
             connecting_details = connecting_details,
             connecting_type = connecting_type,
             create_time = create_time,
             modify_time = modify_time,
             created_by = created_by,
             updated_by = updated_by,
        )
        db.session.add(datasource)
        db.session.commit()
        """The exception may occur as a result of a database constraint violation, such as a unique key.
 In an event of such an error, the code reverses the current transaction by calling."""
    except IntegrityError as e:
            db.session.rollback()
            return {
                 "success" : False,
                 "error" : "datasource already exists."
            }
    return {
         "success": True,
         "datasource": datasource,

         "message" : f"'{datasource.name}' dashboard created successfully.",
    }

