
"""
Performance тесты
"""

import pytest
import time

@pytest.mark.performance
@pytest.mark.slow
class TestCryptoPerformance:
    """Производительность криптографии"""
    
    def test_signing_throughput(self, identity):
        """Пропускная способность подписи"""
        data = {'test': 'data', 'timestamp': time.time()}
        
        start = time.time()
        iterations = 1000
        
        for _ in range(iterations):
            identity.sign(data)
        
        elapsed = time.time() - start
        ops_per_sec = iterations / elapsed
        
        print(f"\nSigning: {ops_per_sec:.0f} ops/sec")
        assert ops_per_sec > 100  # Минимум 100 подписей/сек

@pytest.mark.performance
class TestDHTPerformance:
    """Производительность DHT"""
    
    def test_store_retrieve_latency(self, murnaked):
        """Латентность store/retrieve"""
        import statistics
        
        latencies = []
        
        for i in range(100):
            key = f'perf-key-{i}'
            data = b'x' * 1024
            
            start = time.time()
            murnaked.store(key, data)
            murnaked.retrieve(key)
            latencies.append(time.time() - start)
        
        p50 = statistics.median(latencies)
        p95 = sorted(latencies)[int(len(latencies) * 0.95)]
        
        print(f"\nDHT p50: {p50*1000:.1f}ms, p95: {p95*1000:.1f}ms")
        assert p50 < 0.01  # Менее 10ms