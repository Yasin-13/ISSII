import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from datetime import datetime, timedelta

# Define the tasks with their start and end dates
tasks = [
    ("Project Planning & Requirements", "2024-01-08", "2024-01-14"),
    ("Collect College Content", "2024-01-15", "2024-01-28"),
    ("3D Floor Design (Modeling)", "2024-01-29", "2024-02-25"),
    ("Web Design (UI/UX)", "2024-02-05", "2024-02-18"),
    ("3D Integration & Development", "2024-02-19", "2024-03-10"),
    ("Content Integration", "2024-03-04", "2024-03-17"),
    ("Testing & Debugging", "2024-03-18", "2024-03-31"),
    ("Final Touches & Deployment", "2024-04-01", "2024-04-07"),
    ("Feedback & Documentation", "2024-04-08", "2024-04-15"),
]

# Convert dates to datetime objects
for i in range(len(tasks)):
    tasks[i] = (tasks[i][0], datetime.strptime(tasks[i][1], "%Y-%m-%d"), datetime.strptime(tasks[i][2], "%Y-%m-%d"))

# Plotting
fig, ax = plt.subplots(figsize=(12, 6))

# Create bars for each task
for i, (task, start, end) in enumerate(tasks):
    ax.barh(task, (end - start).days, left=start, color="skyblue")

# Formatting the x-axis
ax.xaxis.set_major_locator(mdates.WeekdayLocator(interval=1))
ax.xaxis.set_major_formatter(mdates.DateFormatter("%b %d"))
plt.xticks(rotation=45)
plt.title("Gantt Chart: 3D College Floor View Website Project")
plt.xlabel("Date")
plt.ylabel("Task")
plt.grid(axis='x', linestyle='--', alpha=0.7)
plt.tight_layout()

plt.show()
