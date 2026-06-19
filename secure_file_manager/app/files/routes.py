try:
    Share.query.filter_by(file_id=file_id).delete()
    db.session.delete(file)
    db.session.commit()
except Exception as e:
    db.session.rollback()
    current_app.logger.error(f"DELETE ERROR: {str(e)}")
    flash(str(e))
    return redirect(url_for('files.dashboard'))