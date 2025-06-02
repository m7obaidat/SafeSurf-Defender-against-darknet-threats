from flask import jsonify
from app import app
from flask_login import login_required
from nosql_operations import TrafficDB

traffic_db = TrafficDB()

@app.route('/api/traffic/stats')
@login_required
def get_traffic_stats():
    try:
        traffic_counts = traffic_db.get_traffic_counts()
        daily_traffic = traffic_db.get_daily_traffic()
        unique_visitors = traffic_db.get_unique_visitors()
        top_pages = traffic_db.get_top_pages()

        # Format data for charts
        hours = []
        visits = []
        for item in daily_traffic:
            hours.append(f"{item['_id']['date']} {item['_id']['hour']:02d}:00")
            visits.append(item['visits'])

        return jsonify({
            'success': True,
            'data': {
                'chart': {
                    'labels': hours,
                    'visits': visits
                },
                'stats': {
                    'total_traffic': traffic_counts['total_traffic'],
                    'normal_traffic': traffic_counts['normal_traffic'],
                    'suspicious_traffic': traffic_counts['suspicious_traffic'],
                    'unique_visitors': unique_visitors,
                    'top_pages': top_pages
                }
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500 