from waitress import serve 
from icwidget import app

if __name__ == '__main__':
    serve(app, host='0.0.0.0', port=3000, threads=350)
