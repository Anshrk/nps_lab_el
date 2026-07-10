import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import GradientBoostingRegressor
from sklearn.model_selection import train_test_split
from sklearn.metrics import mean_squared_error, r2_score

# Set plot style for a professional look
sns.set_theme(style="whitegrid", palette="muted")

# 1. GENERATE FAKE DATASET
def generate_rf_dataset(n_samples=5000):
    np.random.seed(42)
    
    # Standard RF Bands (GHz)
    bands = np.array([0.433, 0.868, 0.915, 1.575, 1.8, 2.1, 2.4, 3.4, 3.5, 4.9, 5.18, 5.8])
    
    data = {
        'Temp_C': np.random.uniform(10, 45, n_samples),
        'Humidity_pct': np.random.uniform(10, 100, n_samples),
        'Precipitation_mm': np.random.uniform(0, 50, n_samples),
        'Condition_Code': np.random.choice([0, 1, 2, 3], n_samples, p=[0.4, 0.3, 0.2, 0.1]), # 0:Clear, 1:Cloudy, 2:Rain, 3:Fog
        'Start_Freq_GHz': np.random.uniform(0.1, 3.0, n_samples),
        'End_Freq_GHz': np.random.uniform(4.0, 10.0, n_samples)
    }
    
    df = pd.DataFrame(data)
    optimal_freqs = []
    
    # Simulate the physics logic to find the "True" optimal frequency
    for _, row in df.iterrows():
        valid_bands = bands[(bands >= row['Start_Freq_GHz']) & (bands <= row['End_Freq_GHz'])]
        if len(valid_bands) == 0:
            valid_bands = bands # Fallback
            
        scores = []
        for b in valid_bands:
            score = 100
            # Apply weather attenuation penalties (High freq suffers in rain/humidity)
            if b >= 4.0:
                score -= (row['Humidity_pct'] > 70) * 25 + (row['Precipitation_mm'] * 0.8)
            elif b >= 2.0:
                score -= (row['Humidity_pct'] > 85) * 12 + (row['Precipitation_mm'] * 0.3)
                
            if row['Condition_Code'] >= 2: # Rain or Fog
                score -= (15 if b >= 4.0 else 5)
            
            # Bonus for clear weather and high bandwidth
            if row['Condition_Code'] == 0 and b >= 2.4:
                score += 5
                
            scores.append(score)
            
        # Add some Gaussian noise to the best band selection to simulate real-world variance
        best_band = valid_bands[np.argmax(scores)]
        noise = np.random.normal(0, 0.05) 
        optimal_freqs.append(round(best_band + noise, 3))
        
    df['Optimal_Freq_GHz'] = optimal_freqs
    return df

print("Generating synthetic RF dataset...")
df = generate_rf_dataset(5000)
df.to_csv("rf_optimization_dataset.csv", index=False)
print("Dataset saved to 'rf_optimization_dataset.csv'")

# 2. TRAIN GRADIENT BOOSTING MODEL
X = df[['Temp_C', 'Humidity_pct', 'Precipitation_mm', 'Condition_Code', 'Start_Freq_GHz', 'End_Freq_GHz']]
y = df['Optimal_Freq_GHz']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

gbr = GradientBoostingRegressor(n_estimators=100, learning_rate=0.1, max_depth=4, random_state=42)
gbr.fit(X_train, y_train)
y_pred = gbr.predict(X_test)

mse = mean_squared_error(y_test, y_pred)
r2 = r2_score(y_test, y_pred)
print(f"Model Trained! MSE: {mse:.4f} | R2 Score: {r2:.4f}")

# 3. GENERATE VISUALIZATIONS
fig = plt.figure(figsize=(18, 5))

# Plot 1: True vs Predicted Frequencies
ax1 = fig.add_subplot(131)
ax1.scatter(y_test, y_pred, alpha=0.3, color='#378ADD', edgecolor='k')
ax1.plot([y.min(), y.max()], [y.min(), y.max()], 'k--', lw=2)
ax1.set_xlabel('True Optimal Frequency (GHz)', fontsize=12)
ax1.set_ylabel('Predicted Frequency (GHz)', fontsize=12)
ax1.set_title('Gradient Boosting: True vs Predicted', fontsize=14, pad=10)

# Plot 2: Training Deviance (Learning Curve)
ax2 = fig.add_subplot(132)
test_score = np.zeros((gbr.n_estimators,), dtype=np.float64)
for i, y_pred_iter in enumerate(gbr.staged_predict(X_test)):
    test_score[i] = mean_squared_error(y_test, y_pred_iter)

ax2.plot(np.arange(gbr.n_estimators) + 1, gbr.train_score_, 'b-', label='Training Loss', color='#1D9E75')
ax2.plot(np.arange(gbr.n_estimators) + 1, test_score, 'r-', label='Test Loss', color='#D85A30')
ax2.set_xlabel('Boosting Iterations', fontsize=12)
ax2.set_ylabel('Deviance (MSE)', fontsize=12)
ax2.set_title('Convergence Curve', fontsize=14, pad=10)
ax2.legend()

# Plot 3: Feature Importance
ax3 = fig.add_subplot(133)
feature_importance = gbr.feature_importances_
sorted_idx = np.argsort(feature_importance)
pos = np.arange(sorted_idx.shape[0]) + 0.5

ax3.barh(pos, feature_importance[sorted_idx], align='center', color='#534AB7')
ax3.set_yticks(pos, np.array(X.columns)[sorted_idx])
ax3.set_xlabel('Relative Importance', fontsize=12)
ax3.set_title('Variable Importance (Additive Model)', fontsize=14, pad=10)

plt.tight_layout()
plt.savefig('rf_gb_metrics.png', dpi=300)
print("Graphs saved to 'rf_gb_metrics.png'")
plt.show()
