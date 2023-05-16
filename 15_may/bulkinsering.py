from flask import jsonify, request

class Customer():

    
@app.route('/customers', methods=['POST'])
def create_customers():
    data = request.get_json()
    if not data:
        return jsonify({'message': 'No input data provided'}), 400
    
    try:
        # Extract customer information from the request data
        customers = []
        for customer_data in data:
            name = customer_data.get('name')
            email = customer_data.get('email')
            if name and email:
                customer = Customer(name=name, email=email)
                customers.append(customer)
        
        if not customers:
            return jsonify({'message': 'Invalid customer data provided'}), 400
        
        # Bulk insert the customers
        db.session.add_all(customers)
        db.session.commit()
        
        return jsonify({'message': f"{len(customers)} customers created successfully"}), 201
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': str(e)}), 500
    
#