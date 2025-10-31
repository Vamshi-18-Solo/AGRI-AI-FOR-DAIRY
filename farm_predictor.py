import numpy as np
from sklearn.ensemble import RandomForestRegressor
import pickle

# Sample training data (you should replace this with your actual dataset)
X_train = np.array([
    # Land,  Shed Cost,    Feed/Day,   Feed/Month,     Cow Purchase Cost
    [100,    250000,       3000,       90000,          600000],
    [200,    500000,       6000,       180000,         1200000],
    [300,    750000,       9000,       270000,         1800000],
    [400,    1000000,      12000,      360000,         2400000],
    [500,    1250000,      15000,      450000,         3000000],
    [1000,   2500000,      30000,      900000,         6000000],
    [1500,   3750000,      45000,      1350000,        9000000],
    [2000,   5000000,      60000,      1800000,        12000000],
    # Add more training data here
])

# Corresponding number of cows (output)
y_train = np.array([10, 20, 30, 40, 50, 100, 150, 200])  # Example outputs

# Create and train the model
model = RandomForestRegressor(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Save the model
with open('farm_predictor_model.pkl', 'wb') as f:
    pickle.dump(model, f)

def predict_cows(land_size, shed_cost, feed_cost_day, feed_cost_month, cow_purchase_cost):
    """
    Predict number of cows based on input parameters
    """
    features = np.array([[land_size, shed_cost, feed_cost_day, feed_cost_month, cow_purchase_cost]])
    predicted_cows = int(model.predict(features)[0])
    return max(1, predicted_cows)  # Ensure at least 1 cow is predicted

def validate_inputs(land_size, shed_cost, feed_cost_day, feed_cost_month, cow_purchase_cost):
    """
    Validate input parameters
    """
    if any(v <= 0 for v in [land_size, shed_cost, feed_cost_day, feed_cost_month, cow_purchase_cost]):
        raise ValueError("All inputs must be positive numbers")
    
    # Validate feed cost relationship
    if abs(feed_cost_day * 30 - feed_cost_month) > 100:  # Allow small difference due to rounding
        raise ValueError("Monthly feed cost should be approximately 30 times daily feed cost")
