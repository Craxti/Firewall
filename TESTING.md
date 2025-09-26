# Руководство по тестированию Firewall

## Установка зависимостей для тестирования

```bash
pip install -r requirements.txt
```

## Запуск тестов

### Все тесты
```bash
pytest
```

### Только unit тесты
```bash
pytest -m "not integration"
```

### Только интеграционные тесты
```bash
pytest -m integration
```

### С покрытием кода
```bash
pytest --cov=firewall --cov-report=html
```

### Быстрые тесты (исключая медленные)
```bash
pytest -m "not slow"
```

## Проверка качества кода

### Линтинг с flake8
```bash
flake8 firewall tests
```

### Форматирование кода с black
```bash
black firewall tests
```

### Сортировка импортов с isort
```bash
isort firewall tests
```

### Проверка типов с mypy
```bash
mypy firewall
```

## Структура тестов

```
tests/
├── test_set_firewall.py      # Unit тесты для SetFirewall
├── test_windows_adapter.py   # Unit тесты для WindowsFirewallAdapter
├── test_integration.py       # Интеграционные тесты
└── __init__.py
```

## Тестирование на разных платформах

### Linux
```bash
# Требуются права root для полного тестирования
sudo pytest tests/test_set_firewall.py
```

### Windows
```bash
# Требуются права администратора для полного тестирования
pytest tests/test_windows_adapter.py
```

## Примеры тестовых сценариев

### 1. Тест базовой настройки firewall
```python
def test_basic_firewall_setup():
    firewall = SetFirewall(verbose=0, execute=False)
    firewall.flush_rules()
    firewall.allow_dhcp()
    firewall.allow_ping()
    # Проверяем, что команды добавлены
    assert len(firewall.command_list) > 0
```

### 2. Тест правил сетевого транспорта
```python
def test_network_transport_rules():
    firewall = SetFirewall(verbose=0, execute=False)
    firewall.allow_network_transport(
        protocol='tcp',
        direction='inbound',
        ports=[80, 443],
        networks=['192.168.1.0/24'],
        policy='ACCEPT'
    )
    # Проверяем TCP команды
    tcp_commands = [cmd for cmd in firewall.command_list if 'tcp' in cmd.lower()]
    assert len(tcp_commands) > 0
```

### 3. Тест Windows адаптера
```python
def test_windows_adapter():
    adapter = WindowsFirewallAdapter(verbose=0, execute=False)
    adapter.allow_dhcp()
    # Проверяем PowerShell команды
    assert any('New-NetFirewallRule' in cmd for cmd in adapter.command_list)
```

## Непрерывная интеграция

### GitHub Actions
```yaml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: 3.9
    - name: Install dependencies
      run: pip install -r requirements.txt
    - name: Run tests
      run: pytest --cov=firewall
```

## Отладка тестов

### Подробный вывод
```bash
pytest -v -s
```

### Остановка на первой ошибке
```bash
pytest -x
```

### Запуск конкретного теста
```bash
pytest tests/test_set_firewall.py::TestSetFirewall::test_flush_rules
```

## Покрытие кода

После запуска тестов с покрытием, отчет будет доступен в:
- `htmlcov/index.html` - HTML отчет
- `coverage.xml` - XML отчет для CI/CD

## Лучшие практики

1. **Именование тестов**: Используйте описательные имена, начинающиеся с `test_`
2. **Изоляция тестов**: Каждый тест должен быть независимым
3. **Моки**: Используйте моки для внешних зависимостей
4. **Параметризация**: Используйте `@pytest.mark.parametrize` для множественных случаев
5. **Фикстуры**: Используйте `@pytest.fixture` для общих настроек

## Пример параметризованного теста

```python
@pytest.mark.parametrize("protocol,ports,expected", [
    ("tcp", [80, 443], "tcp"),
    ("udp", [53], "udp"),
])
def test_protocol_handling(protocol, ports, expected):
    firewall = SetFirewall(verbose=0, execute=False)
    firewall.allow_network_transport(
        protocol=protocol,
        direction='inbound',
        ports=ports,
        policy='ACCEPT'
    )
    assert any(expected in cmd.lower() for cmd in firewall.command_list)
```
