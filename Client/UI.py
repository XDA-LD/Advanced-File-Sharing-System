from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, session
import os
from werkzeug.utils import secure_filename
from Client import Client

app = Flask(__name__)
app.template_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
app.config['SECRET_KEY'] = '1234'
app.config['TEMPORARY_UPLOAD_FOLDER'] = 'temp'
os.makedirs(app.config['TEMPORARY_UPLOAD_FOLDER'], exist_ok=True)
client = Client()


@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))

    # Use client to get files
    user_file_details = client.listAllFiles()
    return render_template('index.html', username=session['username'], files=user_file_details)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Use client's login method
        if client.login(username, password):
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('index'))

        flash('Invalid username or password', 'danger')

    return render_template('login.html')


@app.route('/logout')
def logout():
    # Before logging out, disconnect from server if needed
    if 'username' in session:
        client.disconnectFromServer()

    session.pop('username', None)
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))


# Inside UI.py

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'username' not in session:
        flash("Please log in to upload files.", "warning")
        return redirect(url_for('login'))

    if 'file' not in request.files:
        flash('No file part selected.', 'danger')
        return redirect(request.url) # Redirect back to index (or upload page)

    file = request.files['file']

    if file.filename == '':
        flash('No file selected for upload.', 'danger')
        return redirect(request.url)

    if file:
        filename = secure_filename(file.filename)
        # Define user-specific temporary storage within the UI's temp folder
        user_temp_folder = os.path.join(app.config['TEMPORARY_UPLOAD_FOLDER'], session['username'])
        os.makedirs(user_temp_folder, exist_ok=True)

        # Save the file temporarily on the UI server's disk
        temp_file_path = os.path.join(user_temp_folder, filename)
        try:
            file.save(temp_file_path)
        except Exception as e:
             flash(f"Error saving file temporarily: {e}", "danger")
             return redirect(url_for('index'))

        # Ensure client is connected (might need re-login if connection dropped)
        # Check if client knows its username and matches the session
        if not client.connected or client.username != session['username']:
             flash("Connection issue or session mismatch. Please log in again.", "warning")
             # Clean up temp file before redirecting
             if os.path.exists(temp_file_path): os.remove(temp_file_path)
             return redirect(url_for('logout'))

        # --- FIX: Call uploadFileAction with only 2 arguments (plus self) ---
        upload_success = client.uploadFileAction(temp_file_path, filename)

        # Clean up the temporary file regardless of success/failure
        if os.path.exists(temp_file_path):
            try:
                os.remove(temp_file_path)
            except Exception as e:
                 print(f"Warning: Failed to remove temporary file {temp_file_path}: {e}")


        if upload_success:
            flash(f"File '{filename}' successfully uploaded.", 'success')
        else:
            flash(f"Error uploading file '{filename}' to the server.", 'danger')

    return redirect(url_for('index'))


@app.route('/download/<filename>')
def download_file(filename):
    if 'username' not in session:
        return redirect(url_for('login'))

    user_folder = os.path.join(app.config['TEMPORARY_UPLOAD_FOLDER'], session['username'])
    save_path = os.path.join(user_folder, filename)

    # Use client to download the file
    download_success = client.downloadFileAction(filename, save_path)

    if download_success:
        return send_from_directory(user_folder, filename, as_attachment=True)
    else:
        flash('Error downloading file from server', 'danger')
        return redirect(url_for('index'))


@app.route('/delete/<filename>')
def delete_file(filename):
    if 'username' not in session:
        return redirect(url_for('login'))

    delete_success = client.deleteFile(filename)

    if delete_success:
        flash(f'File {filename} deleted successfully', 'success')
    else:
        flash(f'You do not have permission to delete {filename} from server', 'danger')

    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)