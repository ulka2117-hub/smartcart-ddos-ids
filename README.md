# Smart Cart DDoS Detection IDS

## Project Overview
Simulation-based DDoS detection system for 
retail smart cart IoT networks using 
lightweight Random Forest IDS deployed 
at WiFi access point level.

## Project Structure
- smartcart-sim.cc — NS-3.40 simulation
- extract_features_final.py — Feature extraction
- train_model.py — RF model training
- router_ids.py — Router alert system
- smartcart_dataset_final.csv — Generated dataset
- smartcart_rf_model.pkl — Trained model
- router_ids_alerts.csv — IDS alert log

## Requirements
- NS-3.40
- Python 3.10
- scikit-learn
- pandas
- numpy
- dpkt
- scipy

## How to Run
### Step 1 — Run simulation
./ns3 run scratch/smartcart-sim

### Step 2 — Extract features
python3 extract_features_final.py

### Step 3 — Train model
python3 train_model.py

### Step 4 — Run router IDS
python3 router_ids.py

## Results
- Dataset: 7099 samples
- Accuracy: 97.60%
- F1 Score: 0.9477
- AUC: 0.9962
- False Positive Rate: 0.27%
- All 5 attack phases deteced
