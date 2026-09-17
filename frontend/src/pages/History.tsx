import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Globe2, Link2, FileText, Home } from 'lucide-react';
import { fetchHistory } from '../lib/api';
import type { FileLookup, HistoryItem, IPLookup, UrlLookup } from '../lib/types';
import { GlassCard } from '../components/GlassCard';
import { IpResultCard, UrlResultCard, FileResultCard } from '../components/ResultCard';

const TYPE_ICON = { ip: Globe2, url: Link2, file: FileText } as const;

function scoreColor(score: number): string {
  if (score >= 60) return 'var(--risk-high)';
  if (score >= 30) return 'var(--risk-medium)';
  if (score > 0) return 'var(--risk-low)';
  return 'var(--risk-clean)';
}

export function History() {
  const navigate = useNavigate();
  const [items, setItems] = useState<HistoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<HistoryItem | null>(null);

  useEffect(() => {
    fetchHistory(50).then((data) => {
      setItems(data);
      setLoading(false);
    });
  }, []);

  return (
    <div style={{ maxWidth: 900, margin: '0 auto' }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12 }}>
        <div>
          <h1 style={{ fontSize: 24, fontWeight: 700, marginBottom: 6 }}>Lookup History</h1>
          <p style={{ fontSize: 13, color: 'var(--text-mid)', marginBottom: 24 }}>
            Recently cached lookups across IPs, URLs, and files. Click a row to view the full result.
          </p>
        </div>
        <button
          onClick={() => navigate('/')}
          style={{
            display: 'flex', alignItems: 'center', justifyContent: 'center', width: 38, height: 38, borderRadius: 10,
            border: '1px solid rgba(255,255,255,0.14)', background: 'rgba(255,255,255,0.05)',
            color: 'var(--text-hi)', cursor: 'pointer', flexShrink: 0,
          }}
          title="Home"
        >
          <Home size={16} />
        </button>
      </div>

      {selected && (
        <div style={{ marginBottom: 24 }}>
          <button
            onClick={() => setSelected(null)}
            style={{ background: 'none', border: 'none', color: 'var(--text-mid)', fontSize: 12.5, cursor: 'pointer', marginBottom: 12, padding: 0 }}
          >
            ← Back to list
          </button>
          {selected.type === 'ip' && <IpResultCard data={selected.detail as IPLookup} />}
          {selected.type === 'url' && <UrlResultCard data={selected.detail as UrlLookup} />}
          {selected.type === 'file' && <FileResultCard data={selected.detail as FileLookup} />}
        </div>
      )}

      {!selected && (
        <GlassCard style={{ padding: 0 }}>
          {loading ? (
            <div style={{ padding: 24, fontSize: 13, color: 'var(--text-dim)' }}>Loading…</div>
          ) : items.length === 0 ? (
            <div style={{ padding: 24, fontSize: 13, color: 'var(--text-dim)' }}>No lookups yet — run one from the Lookup page.</div>
          ) : (
            items.map((item, i) => {
              const Icon = TYPE_ICON[item.type];
              return (
                <div
                  key={`${item.type}-${item.key}-${i}`}
                  onClick={() => setSelected(item)}
                  className="glass-hover"
                  style={{
                    display: 'flex', alignItems: 'center', gap: 12, padding: '14px 18px', cursor: 'pointer',
                    borderBottom: i < items.length - 1 ? '1px solid rgba(255,255,255,0.06)' : undefined,
                  }}
                >
                  <Icon size={16} color="var(--text-dim)" />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 13, fontWeight: 600, fontFamily: 'var(--font-mono)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {item.key}
                    </div>
                    <div style={{ fontSize: 10.5, color: 'var(--text-dim)', marginTop: 2 }}>
                      {item.type.toUpperCase()} · {new Date(item.at).toLocaleString()}
                    </div>
                  </div>
                  <div style={{ fontSize: 13, fontWeight: 700, color: scoreColor(item.score) }}>{item.score}%</div>
                </div>
              );
            })
          )}
        </GlassCard>
      )}
    </div>
  );
}
