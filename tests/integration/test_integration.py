# test_integration.py
"""
Интеграционные тесты - полные сценарии
"""

import pytest
import time
import threading
import tempfile
import shutil

@pytest.mark.integration
@pytest.mark.slow
class TestFullNodeLifecycle:
    """Полный жизненный цикл узла"""
    
    def test_node_start_stop(self, fresh_data_dir):
        """Запуск и остановка узла"""
        from core.node.node import MurnetNode
        
        node = MurnetNode(data_dir=fresh_data_dir, port=0)
        node.start()
        
        assert node.running is True
        assert node.address is not None
        assert node.transport.port > 0
        
        node.stop()
        assert node.running is False
    
    def test_two_nodes_communication(self):
        """Два узла обмениваются сообщениями"""
        # Создаём временные директории
        dir1 = tempfile.mkdtemp()
        dir2 = tempfile.mkdtemp()
        
        node1 = node2 = None
        try:
            from core.node.node import MurnetNode
            node1 = MurnetNode(data_dir=dir1, port=0)
            node2 = MurnetNode(data_dir=dir2, port=0)

            node1.start()
            node2.start()
            
            # Даём время на инициализацию
            time.sleep(0.5)
            
            # Подключаемся
            node2.transport.connect_to(
                '127.0.0.1', 
                node1.transport.port,
                node1.address
            )
            
            # Ждём handshake
            time.sleep(1.0)
            
            # Отправляем сообщение
            received = threading.Event()
            received_msg = [None]
            
            def handler(msg, ip, port):
                received_msg[0] = msg
                received.set()
            
            node1.transport.register_handler(handler)
            
            test_msg = {
                'type': 'test',
                'from': node2.address,
                'to': node1.address,
                'text': 'Hello from node2!'
            }
            
            # Находим пира node1 в node2
            for peer in node2.transport.get_peers():
                if peer['address'] == node1.address:
                    node2.transport.send_to(
                        test_msg,
                        peer['ip'],
                        peer['port'],
                        reliable=True
                    )
                    break
            
            # Ждём доставки
            assert received.wait(timeout=5.0), "Message not received"
            assert received_msg[0]['text'] == 'Hello from node2!'
            
        finally:
            if node1:
                node1.stop()
            if node2:
                node2.stop()
            shutil.rmtree(dir1, ignore_errors=True)
            shutil.rmtree(dir2, ignore_errors=True)