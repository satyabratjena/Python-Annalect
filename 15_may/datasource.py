
@datasource_api.route("/datasource", methods=["POST"])
@auth_required(json=True)
def bulk_insert_datasource():
    bulk_insert = request.json.get()
    if not bulk_insert:
        return {"message": "No data given for input"}, 400
    
    #this try-except block to catch exceptions may occur while adding data
    try:
        bulk_insert = ast.literal_eval(bulk_insert)
        for item in bulk_insert:
            DataSource.query.filter_by(id=item["id"]).insert(item)

            db.session.commit()

            if not bulk_insert:
                return {"message": "Invalid input data"}, 400
            
            db.session.add_all(bulk_insert)
            db.session.commit()

            return { "status": True,
                "message": f"{len(bulk_insert)} customers added successfully"}, 201
        
    except Exception as e:
        db.session.rollback()
        return {"success": False, "message": "Invalid data input"}, 400
    
    