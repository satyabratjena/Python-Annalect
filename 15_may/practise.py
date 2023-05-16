
@datasource_api.route("/datasource", methods=["POST"])
@auth_required(json=True)
def insert_datasource():
    data = request.get_json()
    if not data:
        return {"message": "No data given for input"}, 400

    if isinstance(data, list):
        # Bulk insertion
        try:
            data_sources = []

            for item in data:
                data_source = DataSource(
                    id=item.get("id"),
                    name=item.get("name"),
                    connection_details=item.get("connection_details"),
                    connection_type=item.get("connection_type")
                )
                data_sources.append(data_source)

            if not data_sources:
                return {"message": "Invalid input data"}, 400

            db.session.add_all(data_sources)
            db.session.commit()

            return {
                "status": True,
                "message": f"{len(data_sources)} data sources added successfully"
            }, 201

        except Exception as e:
            db.session.rollback()
            return {"success": False, "message": "Invalid data input"}, 400
    else:
        # Single insertion
        try:
            data_source = DataSource(
                id=data.get("id"),
                name=data.get("name"),
                connection_details=data.get("connection_details"),
                connection_type=data.get("connection_type")
            )
            db.session.add(data_source)
            db.session.commit()

            return {
                "status": True,
                "message": "Data source added successfully"
            }, 201

        except Exception as e:
            db.session.rollback()
            return {"success": False, "message": "Invalid data input"}, 400

