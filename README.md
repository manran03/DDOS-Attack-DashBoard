# DDoS Attack Data Dashboard

This project is a **DDoS Attack Data Dashboard** built using Python, Dash, and Elasticsearch. The dashboard visualizes DDoS attack data, allowing users to explore various attack metrics, such as attack types, number of attacks, unique victim IPs, and average attack durations over time. It also provides interactive visualizations for analyzing attack trends.

## Features
- **Summary Cards**: Display key metrics like total attacks, unique victim IPs, types of attacks, and the average attack duration.
- **Interactive Pie Chart**: Visualizes the distribution of attack types.
- **Line Chart**: Displays the top 3 attack types over time.
- **Stacked Column Chart**: Shows the distribution of attack types over time in a stacked format.
- **Bar Chart**: Visualizes the top 10 victim IPs targeted by DDoS attacks.
- **Tile Chart**: Presents hierarchical data showing the relationship between attack types, countries, autonomous system organizations, and average attack durations.

## Project Structure
- **`DDoSDashboardQueries`**: This class encapsulates all the queries needed to interact with the Elasticsearch instance. It retrieves data for various visualizations like pie charts, line charts, bar charts, and summary statistics.
- **`DDoSDashboard`**: This class defines the layout of the dashboard and handles the logic to update the graphs and summary cards. It uses Dash Bootstrap Components (for layout) and Plotly (for interactive charts).

## Technologies Used
- **Dash**: A web application framework used to build the interactive dashboard.
- **Elasticsearch**: A distributed search and analytics engine used to store and query DDoS attack data.
- **Plotly**: A graphing library used to create interactive and visually appealing charts.
- **Dash Bootstrap Components**: A collection of Bootstrap components for layout and styling.

## Visualizations
- **Summary Cards**: Show key statistics such as total attacks, unique victim IPs, attack types, and average attack durations.
- **Pie Chart**: Displays the distribution of attack types.
- **Line Chart**: Visualizes the top three attack types over time, with each attack type represented as a line.
- **Stacked Column Chart**: Shows the count of different attack types over time in a stacked format.
- **Bar Graph**: Shows the top 10 victim IP addresses based on the number of attacks.
- **Tile Chart**: Displays a treemap of the relationship between attack types, country, and organization, colored by the average duration of the attacks.

## Setup and Installation

### Prerequisites
Ensure that you have the following installed on your system:
- Python 3.7+
- Elasticsearch (for data storage and retrieval)
- Environment variables (`.env` file) containing the `ELASTICSEARCH_CONNECTION_STRING`

## How It Works
Elasticsearch Queries: The dashboard interacts with an Elasticsearch instance using the DDoSDashboardQueries class. This class contains multiple methods that retrieve data from Elasticsearch using specific queries, such as aggregating attack types, counting victim IPs, and calculating attack durations.

Dashboard Layout: The DDoSDashboard class defines the layout of the dashboard using Dash and Dash Bootstrap Components. It includes an input field for selecting the number of days to visualize and several cards to display summary statistics.

Dynamic Visualizations: When the user submits the form with the number of days, the dashboard updates with fresh data, showing charts like pie charts, line charts, and stacked bar charts. These charts are generated using Plotly, a powerful graphing library for Python.

Screenshots
![image](https://github.com/user-attachments/assets/45b35272-ca39-491e-8283-7a5b21a141f7)

![image](https://github.com/user-attachments/assets/67259b6d-0960-4b9e-ad74-ccb1d7b2e936)



License
This project is licensed under the MIT License.
