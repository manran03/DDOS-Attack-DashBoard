import dash
from dash import dcc, html, Input, Output
import dash_bootstrap_components as dbc
import plotly.express as px
import plotly.graph_objs as go
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
import pandas as pd
from dotenv import load_dotenv
import os

class DDoSDashboardQueries:
    def __init__(self, es_host, index_pattern):
        self.es = Elasticsearch(es_host)
        self.index_pattern = index_pattern

    def get_pie_chart_data(self, days):
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        query = {
            "query": {
                "range": {
                    "timestamp": {
                        "gte": start_date,
                        "lte": end_date
                    }
                }
            },
            "aggs": {
                "attack_types": {
                    "terms": {
                        "field": "attack_type.keyword"
                    }
                }
            }
        }
        return self.es.search(index=self.index_pattern, body=query)

    def get_top_three_attack_types_line_chart(self, days):
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        query = {
            "query": {
                "range": {
                    "timestamp": {
                        "gte": start_date,
                        "lte": end_date
                    }
                }
            },
            "aggs": {
                "top_attack_types": {
                    "terms": {
                        "field": "attack_type.keyword",
                        "size": 3
                    },
                    "aggs": {
                        "over_time": {
                            "date_histogram": {
                                "field": "timestamp",
                                "calendar_interval": "day"
                            }
                        }
                    }
                }
            }
        }
        return self.es.search(index=self.index_pattern, body=query)

    def get_stacked_column_chart_data(self, days):
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        query = {
            "query": {
                "range": {
                    "timestamp": {
                        "gte": start_date,
                        "lte": end_date
                    }
                }
            },
            "aggs": {
                "attacks_over_time": {
                    "date_histogram": {
                        "field": "timestamp",
                        "calendar_interval": "day"
                    },
                    "aggs": {
                        "attack_types": {
                            "terms": {
                                "field": "attack_type.keyword"
                            }
                        }
                    }
                }
            }
        }
        return self.es.search(index=self.index_pattern, body=query)

    def get_top_victim_ips(self, days):
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        query = {
            "query": {
                "range": {
                    "timestamp": {
                        "gte": start_date,
                        "lte": end_date
                    }
                }
            },
            "aggs": {
                "top_victim_ips": {
                    "terms": {
                        "field": "victim_ip_range.keyword",
                        "size": 10
                    }
                }
            }
        }
        return self.es.search(index=self.index_pattern, body=query)

    def get_tile_chart_data(self, days):
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        query = {
            "query": {
                "range": {
                    "timestamp": {
                        "gte": start_date,
                        "lte": end_date
                    }
                }
            },
            "aggs": {
                "type_of_attack": {
                    "terms": {
                        "field": "attack_type.keyword"
                    },
                    "aggs": {
                        "country": {
                            "terms": {
                                "field": "geoip.country.keyword"
                            },
                            "aggs": {
                                "autonomous_system_organization": {
                                    "terms": {
                                        "field": "geoip.autonomous_system_organization.keyword"
                                    },
                                    "aggs": {
                                        "attack_duration": {
                                            "avg": {
                                                "script": {
                                                    "source": "doc['last_updated_time'].value.toInstant().toEpochMilli() - doc['timestamp'].value.toInstant().toEpochMilli()"
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        response = self.es.search(index=self.index_pattern, body=query, size=0)
        return response['aggregations']['type_of_attack']['buckets']

    def get_single_data_card_values(self, days):
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        total_attacks_query = {
            "query": {
                "range": {
                    "timestamp": {
                        "gte": start_date,
                        "lte": end_date
                    }
                }
            }
        }
        
        total_attacks = self.es.count(index=self.index_pattern, body=total_attacks_query)['count']
        
        unique_victim_ips_query = {
            "query": {
                "range": {
                    "timestamp": {
                        "gte": start_date,
                        "lte": end_date
                    }
                }
            },
            "aggs": {
                "unique_victim_ips": {
                    "cardinality": {
                        "field": "victim_ip_range.keyword"
                    }
                }
            }
        }
        
        unique_victim_ips = self.es.search(index=self.index_pattern, body=unique_victim_ips_query)['aggregations']['unique_victim_ips']['value']
        
        attack_types_query = {
            "query": {
                "range": {
                    "timestamp": {
                        "gte": start_date,
                        "lte": end_date
                    }
                }
            },
            "aggs": {
                "attack_types": {
                    "cardinality": {
                        "field": "attack_type.keyword"
                    }
                }
            }
        }
        
        attack_types = self.es.search(index=self.index_pattern, body=attack_types_query)['aggregations']['attack_types']['value']
        
        avg_attack_duration_query = {
            "query": {
                "range": {
                    "timestamp": {
                        "gte": start_date,
                        "lte": end_date
                    }
                }
            },
            "aggs": {
                "avg_attack_duration": {
                    "avg": {
                        "script": {
                            "source": "doc['last_updated_time'].value.toInstant().toEpochMilli() - doc['timestamp'].value.toInstant().toEpochMilli()"
                        }
                    }
                }
            }
        }
        
        avg_attack_duration = self.es.search(index=self.index_pattern, body=avg_attack_duration_query)['aggregations']['avg_attack_duration']['value']
        
        return {
            "total_attacks": total_attacks,
            "unique_victim_ips": unique_victim_ips,
            "attack_types": attack_types,
            "avg_attack_duration": avg_attack_duration
        }

class DDoSDashboard:
    def __init__(self, queries, days=7):
        self.queries = queries
        self.days = days

    def create_dashboard(self):
        app = dash.Dash(external_stylesheets=[dbc.themes.BOOTSTRAP])

        app.layout = dbc.Container(
            [
                html.H1("DDOS Attack Data Dashboard", className='text-center my-4'),
                
                # Input and submit button row
                dbc.Row(
                    [
                        dbc.Col(
                            dcc.Input(
                                id='days-input', type='number', value=1, min=1, className='form-control'
                            ), width={"size": 3, "offset": 4}
                        ),
                        dbc.Col(
                            dbc.Button("Submit", id='submit-button', color="primary", className='ml-2'), width="auto"
                        ),
                    ],
                    className="mb-4 justify-content-center"
                ),
                
                # Cards row for summary stats
                dbc.Row(
                    [
                        dbc.Col(
                            dbc.Card(
                                dbc.CardBody(
                                    [
                                        html.H5("Total Attacks", className='card-title'),
                                        html.P(id='total-attacks', className='card-text')
                                    ]
                                ), className="shadow-sm"
                            ), width=3
                        ),
                        dbc.Col(
                            dbc.Card(
                                dbc.CardBody(
                                    [
                                        html.H5("Unique Victim IPs", className='card-title'),
                                        html.P(id='unique-victim-ips', className='card-text')
                                    ]
                                ), className="shadow-sm"
                            ), width=3
                        ),
                        dbc.Col(
                            dbc.Card(
                                dbc.CardBody(
                                    [
                                        html.H5("Attack Types", className='card-title'),
                                        html.P(id='attack-types', className='card-text')
                                    ]
                                ), className="shadow-sm"
                            ), width=3
                        ),
                        dbc.Col(
                            dbc.Card(
                                dbc.CardBody(
                                    [
                                        html.H5("Avg Attack Duration", className='card-title'),
                                        html.P(id='avg-attack-duration', className='card-text')
                                    ]
                                ), className="shadow-sm"
                            ), width=3
                        )
                    ],
                    className="mb-4 justify-content-center"
                ),
                
                # Graphs in cards row
                dbc.Row(
                    [
                        dbc.Col(
                            dbc.Card(
                                dcc.Graph(id='pie-chart', config={'displayModeBar': False}),
                                body=True, className='shadow-sm'
                            ), width=6
                        ),
                        dbc.Col(
                            dbc.Card(
                                dcc.Graph(id='line-chart', config={'displayModeBar': False}),
                                body=True, className='shadow-sm'
                            ), width=6
                        )
                    ],
                    className="mb-4"
                ),
                
                # Stacked column chart row
                dbc.Row(
                    [
                        dbc.Col(
                            dbc.Card(
                                dcc.Graph(id='stacked-column-chart', config={'displayModeBar': False}),
                                body=True, className='shadow-sm'
                            ), width=12
                        )
                    ],
                    className="mb-4"
                ),
                
                # Bar graph and tile chart row
                dbc.Row(
                    [
                        dbc.Col(
                            dbc.Card(
                                dcc.Graph(id='bar-graph', config={'displayModeBar': False}),
                                body=True, className='shadow-sm'
                            ), width=6
                        ),
                        dbc.Col(
                            dbc.Card(
                                dcc.Graph(id='tile-chart', config={'displayModeBar': False}),
                                body=True, className='shadow-sm'
                            ), width=6
                        )
                    ],
                    className="mb-4"
                )
            ],
            fluid=True
        )

        @app.callback(
            [
                Output('total-attacks', 'children'),
                Output('unique-victim-ips', 'children'),
                Output('attack-types', 'children'),
                Output('avg-attack-duration', 'children'),
                Output('pie-chart', 'figure'),
                Output('line-chart', 'figure'),
                Output('stacked-column-chart', 'figure'),
                Output('bar-graph', 'figure'),
                Output('tile-chart', 'figure')
            ],
            [Input('submit-button', 'n_clicks')],
            [dash.dependencies.State('days-input', 'value')]
        )
        def update_dashboard(n_clicks, days):
            card_values = self.queries.get_single_data_card_values(days)
            pie_data = self.queries.get_pie_chart_data(days)
            line_data = self.queries.get_top_three_attack_types_line_chart(days)
            stacked_data = self.queries.get_stacked_column_chart_data(days)
            bar_data = self.queries.get_top_victim_ips(days)
            tile_data = self.queries.get_tile_chart_data(days)

            return (
                f"{card_values['total_attacks']:,}",
                f"{card_values['unique_victim_ips']:,}",
                f"{card_values['attack_types']:,}",
                f"{card_values['avg_attack_duration'] / 1000:.2f} seconds",
                self.create_pie_chart(pie_data),
                self.create_line_chart(line_data),
                self.create_stacked_column_chart(stacked_data),
                self.create_bar_chart(bar_data),
                self.create_tile_chart(tile_data)
            )

        app.run_server(debug=True)

    def create_pie_chart(self, data):
        labels = [bucket['key'] for bucket in data['aggregations']['attack_types']['buckets']]
        values = [bucket['doc_count'] for bucket in data['aggregations']['attack_types']['buckets']]
        
        fig = go.Figure(data=[go.Pie(labels=labels, values=values, hole=.3)])
        fig.update_layout(title_text="Attack Types Distribution")
        return fig

    def create_line_chart(self, data):
        fig = go.Figure()
        for attack_type in data['aggregations']['top_attack_types']['buckets']:
            dates = [datetime.strptime(item['key_as_string'], '%Y-%m-%dT%H:%M:%S.%fZ').strftime('%d/%m/%y') for item in attack_type['over_time']['buckets']]
            counts = [item['doc_count'] for item in attack_type['over_time']['buckets']]
            fig.add_trace(go.Scatter(x=dates, y=counts, mode='lines+markers', name=attack_type['key']))
        
        fig.update_layout(
            title='Top 3 Attack Types Over Time',
            xaxis_title='Date',
            yaxis_title='Number of Attacks',
            xaxis_tickangle=-45  # Rotate x-axis labels to be diagonal
        )
        return fig

    def create_stacked_column_chart(self, data):
        dates = [date['key_as_string'] for date in data['aggregations']['attacks_over_time']['buckets']]
        formatted_dates = [datetime.strptime(date, '%Y-%m-%dT%H:%M:%S.%fZ').strftime('%d/%m/%y') for date in dates]
        
        attack_types = {}
        for date in data['aggregations']['attacks_over_time']['buckets']:
            for attack in date['attack_types']['buckets']:
                if attack['key'] not in attack_types:
                    attack_types[attack['key']] = []
                attack_types[attack['key']].append(attack['doc_count'])
        
        fig = go.Figure()
        for attack_type, counts in attack_types.items():
            fig.add_trace(go.Bar(x=formatted_dates, y=counts, name=attack_type))
        
        fig.update_layout(
            barmode='stack',
            title='Attack Types Distribution Over Time',
            xaxis_title='Date',
            yaxis_title='Count',
            xaxis_tickangle=-45,  # Rotate x-axis labels to be diagonal
            xaxis_tickmode='array',
            xaxis_tickvals=formatted_dates,
            xaxis_ticktext=formatted_dates,
            yaxis_tickformat=',',  # Display y-axis as counts with commas
        )
        
        return fig

    def create_bar_chart(self, data):
        labels = [bucket['key'] for bucket in data['aggregations']['top_victim_ips']['buckets']]
        values = [bucket['doc_count'] for bucket in data['aggregations']['top_victim_ips']['buckets']]
        
        fig = go.Figure(data=[go.Bar(x=labels, y=values)])
        fig.update_layout(title_text="Top Victim IPs", xaxis_title='IP Range', yaxis_title='Number of Attacks')
        return fig

    def create_tile_chart(self, data):
        processed_data = []
        for attack_type in data:
            for country in attack_type['country']['buckets']:
                for aso in country['autonomous_system_organization']['buckets']:
                    processed_data.append({
                        "type_of_attack": attack_type['key'],
                        "country": country['key'],
                        "autonomous_system_organization": aso['key'],
                        "number_of_attacks": aso['doc_count'],
                        "avg_attack_duration": aso['attack_duration']['value'] if aso['attack_duration']['value'] is not None else 0
                    })
        df_tile = pd.DataFrame(processed_data)
        fig = px.treemap(df_tile, path=['type_of_attack', 'country', 'autonomous_system_organization'], values='number_of_attacks',
                         color='avg_attack_duration', color_continuous_scale='Viridis',
                         title='Attack Duration Hierarchical Tile Chart')
        fig.update_layout(uniformtext=dict(minsize=10, mode='hide'))
        return fig

# Initialize the Elasticsearch queries class
load_dotenv()
es_connection_string = os.getenv('ELASTICSEARCH_CONNECTION_STRING')
es_host = es_connection_string 
index_pattern = "a10_amplification_test-*"
queries = DDoSDashboardQueries(es_host, index_pattern)

# Create and run the dashboard
dashboard = DDoSDashboard(queries, days=7)
dashboard.create_dashboard()
