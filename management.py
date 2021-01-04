from flask import Blueprint, request, jsonify
from auth import require_oauth
from authlib.integrations.flask_oauth2 import current_token

blueprint = Blueprint('management', __name__)

def init_app(app, db):
    pass

@blueprint.route('/chores', methods=['POST'])
@require_oauth()
def create_chore():
    if current_token.user.is_admin:
        content = response.json
        print(content)
    else:
        return jsonify({"error": "User is not an admin"}), 403
    