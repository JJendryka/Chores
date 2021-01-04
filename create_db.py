from models import db, User
from app import create_app
app = create_app()
app.app_context().push()
db.create_all()
admin = User(username="admin")
admin.set_password("password")
admin.is_admin = True
db.session.add(admin)
db.session.commit()