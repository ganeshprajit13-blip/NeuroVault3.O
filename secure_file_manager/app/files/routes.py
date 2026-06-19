@files_bp.route('/delete/<int:file_id>', methods=['POST', 'GET'])
@login_required
def delete(file_id):
    try:
        file = File.query.get_or_404(file_id)

        if file.user_id != current_user.id:
            abort(403)

        storage_path = _resolved_storage_path(file.file_path)

        if os.path.exists(storage_path):
            os.remove(storage_path)

        Share.query.filter_by(file_id=file_id).delete()

        db.session.delete(file)

        db.session.commit()

        flash("Deleted Successfully")

    except Exception as e:
        db.session.rollback()
        flash(str(e))
        print("DELETE ERROR:", e)

    return redirect(url_for('files.dashboard'))