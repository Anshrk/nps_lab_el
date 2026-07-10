import time
import sys
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import GradientBoostingRegressor
from sklearn.model_selection import train_test_split
from sklearn.metrics import mean_squared_error, r2_score

# ==========================================
# 1. TERMINAL UI HELPERS
# ==========================================
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def print_step(msg):
    print(f"{Colors.CYAN}[*] {msg}{Colors.ENDC}")

def print_success(msg):
    print(f"{Colors.GREEN}[+] {msg}{Colors.ENDC}")

def simulate_progress_bar(total=50, prefix='Training Model', sleep_time=0.02):
    for i in range(total + 1):
        percent = 100 * (i / float(total))
        bar = '█' * int(percent / 2) + '-' * (50 - int(percent / 2))
        sys.stdout.write(f'\r{Colors.BLUE}{prefix} |{bar}| {percent:.1f}% Complete{Colors.ENDC}')
        sys.stdout.flush()
        time.sleep(sleep_time)
    print()

# ==========================================
# 2. FAKE DATA GENERATOR
# ==========================================
def generate_synthetic_rf_data(n_samples=8000):
    print_step(f"Bootstrapping {n_samples} synthetic RF telemetry samples...")
    np.random.seed(42)
    
    # Generate random environmental conditions
    temp = np.random.uniform(-10, 50, n_samples)
    humidity = np.random.uniform(20, 100, n_samples)
    precip = np.random.exponential(5, n_samples) # Exponential distribution for realistic rain
    condition = np.random.choice([0, 1, 2, 3], n_samples, p=[0.4, 0.3, 0.2, 0.1])
    
    # Generate boundaries
    start_freq = np.random.uniform(0.1, 2.0, n_samples)
    end_freq = np.random.uniform(5.0, 10.0, n_samples)
    
    # Simulate a "True" optimal frequency using a hidden polynomial/logic formula
    # Higher humidity & precip lower the optimal frequency (simulating attenuation)
    base_freq = 5.8 
    attenuation_factor = (humidity * 0.015) + (precip * 0.08) + (condition * 0.5)
    temp_variance = (temp - 20) * 0.01
    
    true_optimal = base_freq - attenuation_factor + temp_variance
    
    # Clip to realistic bounds and add Gaussian noise for realism
    true_optimal = np.clip(true_optimal, start_freq, end_freq)
    true_optimal += np.random.normal(0, 0.15, n_samples) # Adds "real world" noise
    
    df = pd.DataFrame({
        'Temp_C': temp,
        'Humidity_pct': humidity,
        'Precip_mm': precip,
        'Condition_Code': condition,
        'Start_Freq_GHz': start_freq,
        'End_Freq_GHz': end_freq,
        'Optimal_Freq_GHz': true_optimal
    })
    
    time.sleep(0.8) # Fake delay for effect
    return df

# ==========================================
# 3. MODEL TRAINING & EVALUATION
# ==========================================
def main():
    print(f"\n{Colors.HEADER}{Colors.BOLD}=== Weather-Aware RF Gradient Boosting Simulator ==={Colors.ENDC}\n")
    
    # 1. Get Data
    df = generate_synthetic_rf_data()
    print_success("Synthetic dataset generated successfully.")
    
    # 2. Prep for ML
    X = df.drop(columns=['Optimal_Freq_GHz'])
    y = df['Optimal_Freq_GHz']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # 3. Train Model
    print_step("Initializing Gradient Boosting Regressor (n_estimators=150, lr=0.05)...")
    gbr = GradientBoostingRegressor(n_estimators=150, learning_rate=0.05, max_depth=5, random_state=42)
    
    simulate_progress_bar(total=60) # Visual fluff
    gbr.fit(X_train, y_train)
    print_success("Model weights converged.")
    
    # 4. Predict & Metrics
    print_step("Running predictions on holdout test set...")
    y_pred = gbr.predict(X_test)
    mse = mean_squared_error(y_test, y_pred)
    r2 = r2_score(y_test, y_pred)
    
    print(f"\n{Colors.BOLD}Model Diagnostics:{Colors.ENDC}")
    print(f"  {Colors.GREEN}► R² Score : {r2:.4f}{Colors.ENDC} (Highly Predictive)")
    print(f"  {Colors.GREEN}► RMSE     : {np.sqrt(mse):.4f} GHz{Colors.ENDC}\n")
    
    # ==========================================
    # 4. "LEGIT" MATPLOTLIB DASHBOARD
    # ==========================================
    print_step("Rendering telemetry dashboards...")
    
    # Use a professional dark theme
    plt.style.use('dark_background')
    fig = plt.figure(figsize=(16, 5), facecolor='#121212')
    fig.canvas.manager.set_window_title('RF Gradient Boosting Analytics')
    
    # Colors for the UI
    c_blue = '#378ADD'
    c_green = '#1D9E75'
    c_orange = '#D85A30'

    # Subplot 1: Convergence / Loss Curve
    ax1 = fig.add_subplot(131)
    ax1.set_facecolor('#1e1e1e')
    test_score = np.zeros((gbr.n_estimators,), dtype=np.float64)
    for i, y_pred_iter in enumerate(gbr.staged_predict(X_test)):
        test_score[i] = mean_squared_error(y_test, y_pred_iter)
        
    ax1.plot(np.arange(gbr.n_estimators) + 1, gbr.train_score_, label='Training Loss', color=c_blue, lw=2)
    ax1.plot(np.arange(gbr.n_estimators) + 1, test_score, label='Validation Loss', color=c_orange, lw=2)
    ax1.set_xlabel('Boosting Iterations', color='#aaaaaa')
    ax1.set_ylabel('Deviance (MSE)', color='#aaaaaa')
    ax1.set_title('Gradient Boosting Convergence', color='white', pad=15)
    ax1.grid(True, alpha=0.1)
    ax1.legend(facecolor='#121212', edgecolor='#333333')

    # Subplot 2: Feature Importance
    ax2 = fig.add_subplot(132)
    ax2.set_facecolor('#1e1e1e')
    feature_importance = gbr.feature_importances_
    sorted_idx = np.argsort(feature_importance)
    pos = np.arange(sorted_idx.shape[0]) + 0.5
    
    bars = ax2.barh(pos, feature_importance[sorted_idx], align='center', color=c_green)
    ax2.set_yticks(pos, np.array(X.columns)[sorted_idx], color='#cccccc')
    ax2.set_xlabel('Relative Importance (Gain)', color='#aaaaaa')
    ax2.set_title('Environmental Feature Importance', color='white', pad=15)
    ax2.grid(True, axis='x', alpha=0.1)
    
    # Subplot 3: True vs Predicted Scatter
    ax3 = fig.add_subplot(133)
    ax3.set_facecolor('#1e1e1e')
    ax3.scatter(y_test, y_pred, alpha=0.4, color=c_blue, s=15, edgecolors='none')
    
    # Perfect prediction line
    min_val = min(y_test.min(), y_pred.min())
    max_val = max(y_test.max(), y_pred.max())
    ax3.plot([min_val, max_val], [min_val, max_val], color=c_orange, linestyle='--', lw=2)
    
    ax3.set_xlabel('Actual Optimal Freq (GHz)', color='#aaaaaa')
    ax3.set_ylabel('Predicted Optimal Freq (GHz)', color='#aaaaaa')
    ax3.set_title('Prediction Accuracy', color='white', pad=15)
    ax3.grid(True, alpha=0.1)

    plt.tight_layout(pad=2.0)
    print_success("Dashboard rendered! Displaying window...")
    plt.show()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.FAIL}[!] Process aborted by user.{Colors.ENDC}")
        sys.exit(0)