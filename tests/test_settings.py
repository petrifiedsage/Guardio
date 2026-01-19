import pytest
from app import app, db, AppSettings


@pytest.fixture()
def appctx():
    app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite://',
        'SECRET_KEY': 'test',
    })
    with app.app_context():
        db.create_all()
        yield


def test_app_settings_defaults(appctx):
    s = AppSettings()
    db.session.add(s)
    db.session.commit()
    fetched = AppSettings.query.first()
    assert fetched.max_upload_mb >= 1
    assert 'txt' in fetched.allowed_extensions_csv

