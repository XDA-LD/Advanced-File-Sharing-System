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
    user_files = client.listAllFiles()
    return render_template('index.html', username=session['username'], files=user_files)


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


@app.route('/upload', methods=['POST'])
def upload_file():
    if 'username' not in session:
        return redirect(url_for('login'))

    if 'file' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('index'))

    file = request.files['file']

    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('index'))

    if file:
        filename = secure_filename(file.filename)
        user_folder = os.path.join(app.config['TEMPORARY_UPLOAD_FOLDER'], session['username'])

        os.makedirs(user_folder, exist_ok=True)

        # Save a file copy temporarily
        file_path = os.path.join(user_folder, filename)
        file.save(file_path)

        # Use client to upload the file to server
        upload_success = client.uploadFileAction(file_path, filename, session['username'])

        if upload_success:
            flash('File successfully uploaded', 'success')
            # If upload is done, clean up the temporary file
            if os.path.exists(file_path):
                os.remove(file_path)
        else:
            flash('Error uploading file to server', 'danger')
            # If upload fails, attempt to clean up the temporary file
            if os.path.exists(file_path):
                os.remove(file_path)

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