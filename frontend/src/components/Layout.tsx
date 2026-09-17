import type { ReactNode } from 'react';

export function BackgroundScene() {
  return <div className="bg-scene" />;
}

export function Layout({ children }: { children: ReactNode }) {
  return (
    <div style={{ minHeight: '100vh' }}>
      <BackgroundScene />
      <main style={{ padding: 24, minWidth: 0 }}>{children}</main>
    </div>
  );
}
