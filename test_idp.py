import matplotlib.pyplot as plt
import matplotlib.patches as patches
import numpy as np
import os

# Set global academic styling
plt.style.use('seaborn-v0_8-paper')
plt.rcParams.update({'font.family': 'serif', 'font.size': 10})

def generate_fig1_ml_boosting():
    """Fig 1: Gradient Boosting Convergence Graph"""
    fig, ax = plt.subplots(figsize=(6, 4))
    epochs = np.arange(1, 201)
    train_loss = 2.5 * np.exp(-epochs / 20) + 0.1 * np.random.rand(200) + 0.5
    val_loss = 2.4 * np.exp(-epochs / 25) + 0.15 * np.random.rand(200) + 0.6

    ax.plot(epochs, train_loss, label='Training Loss', color='#1f77b4')
    ax.plot(epochs, val_loss, label='Validation Loss', color='#ff7f0e')
    ax.set_title('Surrogate Model: Training Convergence')
    ax.set_xlabel('Boosting Iterations')
    ax.set_ylabel('MSE Loss (Scaled)')
    ax.legend()
    ax.grid(True, linestyle='--', alpha=0.6)
    plt.tight_layout()
    plt.savefig('placeholder_fig1.png', dpi=300)
    plt.close()

def generate_fig2_block_diagram():
    """Fig 2: RF Energy Harvesting Block Diagram"""
    fig, ax = plt.subplots(figsize=(8, 3))
    ax.axis('off')

    blocks = ["Antenna", "Impedance\nMatching", "Multi-band\nRectification", "DC-DC\nBoost", "IoT Sensor\nLoad"]
    x_pos = [0, 2.5, 5, 7.5, 10]

    for i, text in enumerate(blocks):
        rect = patches.Rectangle((x_pos[i], 1), 1.8, 1, linewidth=1.5, edgecolor='black', facecolor='#e6f2ff')
        ax.add_patch(rect)
        ax.text(x_pos[i] + 0.9, 1.5, text, ha='center', va='center', fontsize=9, weight='bold')

        if i < len(blocks) - 1:
            ax.annotate('', xy=(x_pos[i+1], 1.5), xytext=(x_pos[i]+1.8, 1.5),
                        arrowprops=dict(arrowstyle="->", lw=1.5))

    ax.set_xlim(-0.5, 12.5)
    ax.set_ylim(0, 3)
    plt.tight_layout()
    plt.savefig('placeholder_fig2.png', dpi=300)
    plt.close()

def generate_fig3_schematic():
    """Fig 3: Mock RF Circuit Schematic"""
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.axis('off')

    # Draw mock schematic grid and components
    ax.plot([1, 8], [2, 2], color='black', lw=1.5) # Main line
    ax.plot([2, 2], [2, 1], color='black', lw=1.5) # Ground drop
    ax.plot([4, 4], [2, 3], color='black', lw=1.5) # Component up
    ax.plot([6, 6], [2, 1], color='black', lw=1.5) # Component down

    # Add dummy components (capacitors/inductors)
    ax.add_patch(patches.Rectangle((3.8, 3), 0.4, 0.8, fill=False, lw=1.5))
    ax.add_patch(patches.Rectangle((5.8, 0.2), 0.4, 0.8, fill=False, lw=1.5))
    ax.add_patch(patches.Circle((1, 2), 0.1, color='black'))
    ax.add_patch(patches.Circle((8, 2), 0.1, color='black'))

    ax.text(1, 2.3, "RF IN\n(-15 dBm)", ha='center')
    ax.text(8, 2.3, "DC OUT\n(3.3V)", ha='center')
    ax.text(4, 4, "Matching Network", ha='center', color='blue')
    ax.text(6, -0.2, "Rectifier Diodes", ha='center', color='red')

    ax.set_xlim(0, 9)
    ax.set_ylim(-1, 5)
    plt.tight_layout()
    plt.savefig('placeholder_fig3.png', dpi=300)
    plt.close()

def generate_fig4_pcb():
    """Fig 4: Mock 2D PCB Layout"""
    fig, ax = plt.subplots(figsize=(6, 5))
    ax.set_facecolor('#001b36') # Dark blue PCB background
    ax.set_xticks([])
    ax.set_yticks([])

    # Generate random trace lines
    np.random.seed(42)
    for _ in range(30):
        x = np.random.uniform(0, 10, 2)
        y = np.random.uniform(0, 10, 2)
        ax.plot(x, y, color='#cc0000', lw=2, alpha=0.8) # Red top copper

    for _ in range(20):
        x = np.random.uniform(0, 10, 2)
        y = np.random.uniform(0, 10, 2)
        ax.plot(x, y, color='#0066cc', lw=2, alpha=0.6) # Blue bottom copper

    # Generate vias/pads
    vias_x = np.random.uniform(1, 9, 40)
    vias_y = np.random.uniform(1, 9, 40)
    ax.scatter(vias_x, vias_y, color='#d4af37', s=40, edgecolors='black', zorder=5) # Gold pads

    # Main IC
    ax.add_patch(patches.Rectangle((4, 4), 2, 2, facecolor='#2b2b2b', edgecolor='silver', lw=2, zorder=10))
    ax.text(5, 5, "BQ25570", color='white', ha='center', va='center', fontsize=8, zorder=11)

    ax.set_xlim(0, 10)
    ax.set_ylim(0, 10)
    plt.tight_layout()
    plt.savefig('placeholder_fig4.png', dpi=300, bbox_inches='tight')
    plt.close()

def generate_fig5_s11_plot():
    """Fig 5: Optimized S11 Return Loss Graph"""
    fig, ax = plt.subplots(figsize=(6, 4))
    freq = np.linspace(2.0, 5.0, 500)

    # Simulate a deep resonance dip at 3.4 GHz
    s11 = -2 - 25 * np.exp(-((freq - 3.4) / 0.15)**2)
    s11 += 0.5 * np.sin(freq * 10) # Add slight ripple

    ax.plot(freq, s11, color='red', lw=1.5, label='Optimized S11')
    ax.axhline(-10, color='black', linestyle='--', lw=1, label='-10 dB Threshold')

    # Annotate the peak
    min_idx = np.argmin(s11)
    ax.annotate(f'{freq[min_idx]:.2f} GHz\n{s11[min_idx]:.1f} dB',
                xy=(freq[min_idx], s11[min_idx]), xytext=(freq[min_idx]+0.3, s11[min_idx]+5),
                arrowprops=dict(facecolor='black', shrink=0.05, width=1, headwidth=5))

    ax.set_title('Post-Optimization Return Loss (S11)')
    ax.set_xlabel('Frequency (GHz)')
    ax.set_ylabel('Magnitude (dB)')
    ax.set_ylim(-35, 0)
    ax.legend()
    ax.grid(True, linestyle=':', alpha=0.7)
    plt.tight_layout()
    plt.savefig('placeholder_fig5.png', dpi=300)
    plt.close()

if __name__ == "__main__":
    print("Generating academic placeholders...")
    generate_fig1_ml_boosting()
    generate_fig2_block_diagram()
    generate_fig3_schematic()
    generate_fig4_pcb()
    generate_fig5_s11_plot()
    print("Done! Check your directory for placeholder_fig1.png to placeholder_fig5.png.")
