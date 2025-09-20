import pandas as pd
import matplotlib.pyplot as plt
import os

# Read CSV (make sure CSV is in the same folder or give full path)
df = pd.read_csv("Semgrep_findings_coding.csv")

severity_colors = {'Low': '#a6cee3', 'Medium': '#1f78b4', 'High': '#b2df8a'}
projects = df['Project'].unique()

# Create output directory if not exists
output_dir = "figures"
os.makedirs(output_dir, exist_ok=True)

for project in projects:
    proj_df = df[df['Project'] == project]
    grouped = proj_df.groupby(['CWE', 'Severity'])['Occurances'].sum().reset_index()
    
    # Inner layer: CWEs total
    cwe_counts = grouped.groupby('CWE')['Occurances'].sum()
    
    # Outer layer: severity distribution per CWE
    outer_sizes = []
    outer_colors = []
    for cwe in cwe_counts.index:
        for sev in ['Low','Medium','High']:
            val = grouped[(grouped['CWE'] == cwe) & (grouped['Severity'] == sev)]['Occurances'].sum()
            if val > 0:
                outer_sizes.append(val)
                outer_colors.append(severity_colors[sev])
    
    fig, ax = plt.subplots(figsize=(8, 8))
    # Inner pie
    ax.pie(cwe_counts.values, labels=cwe_counts.index, radius=1,
           wedgeprops=dict(width=0.3, edgecolor='w'))
    # Outer pie
    ax.pie(outer_sizes, radius=1.3,
           wedgeprops=dict(width=0.3, edgecolor='w'),
           colors=outer_colors, labels=['']*len(outer_sizes))
    
    # Legend
    handles = [plt.Line2D([0], [0], color=color, lw=10) for color in severity_colors.values()]
    ax.legend(handles, severity_colors.keys(), title="Severity", loc='upper left')
    
    plt.title(f"{project}: CWE (inner) and Severity (outer)", fontsize=14)
    
    # Save figure locally
    pdf_file = os.path.join(output_dir, f"{project}_CWE_Severity.pdf")
    fig.savefig(pdf_file, bbox_inches='tight')
    print(f"Saved {pdf_file}")
    
    plt.show()
