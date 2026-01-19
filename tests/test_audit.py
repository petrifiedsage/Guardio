import pytest
from app import app, db, AuditBlock, _compute_block_hash


@pytest.fixture()
def client():
    app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite://',
        'WTF_CSRF_ENABLED': False,
        'SECRET_KEY': 'test',
    })
    with app.app_context():
        db.create_all()
    with app.test_client() as client:
        yield client


def test_compute_block_hash_deterministic(client):
    h1 = _compute_block_hash(0, '2020-01-01T00:00:00Z', None, 'GENESIS', '{}', '0'*64)
    h2 = _compute_block_hash(0, '2020-01-01T00:00:00Z', None, 'GENESIS', '{}', '0'*64)
    assert h1 == h2


def test_chain_integrity_ok(client):
    with app.app_context():
        # Clear any automatically created genesis block to start fresh
        db.session.query(AuditBlock).delete()
        db.session.commit()

        prev = '0'*64
        # create simple 2-block chain
        for idx in range(2):
            payload_hash = _compute_block_hash(idx, '2020-01-01T00:00:00Z', None, 'EVT', '{}', prev)
            b = AuditBlock(index=idx, timestamp=None, actor_user_id=None, action='EVT', metadata_json='{}', previous_hash=prev, block_hash=payload_hash)
            db.session.add(b)
            prev = payload_hash
        db.session.commit()
        blocks = AuditBlock.query.order_by(AuditBlock.index.asc()).all()
        assert len(blocks) == 2

