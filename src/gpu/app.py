from flask import Flask, render_template, request

app = Flask(__name__)


# Определение маршрута для главной страницы
@app.route('/')
def home():
    return render_template('index.html')


@app.route('/process', methods=['POST'])
def process():
    source_ip = request.form['source_ip']
    destination_ip = request.form['destination_ip']

    process_packet(source_ip, destination_ip)

    return 'Packet processed successfully'


def process_packet(source_ip, destination_ip):
    print('Source IP:', source_ip)
    print('Destination IP:', destination_ip)

    if source_ip == destination_ip:
        print('Blocked packet:', source_ip, '->', destination_ip)
    else:
        print('Allow packet:', source_ip, '->', destination_ip)


if __name__ == '__main__':
    app.run(debug=True)
