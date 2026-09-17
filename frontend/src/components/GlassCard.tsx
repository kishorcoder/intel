import type { CSSProperties, ReactNode } from 'react';

export function GlassCard({
  children,
  className = '',
  hover = false,
  style,
  onClick,
}: {
  children: ReactNode;
  className?: string;
  hover?: boolean;
  style?: CSSProperties;
  onClick?: () => void;
}) {
  return (
    <div
      className={`glass glass-specular ${hover ? 'glass-hover' : ''} ${className}`}
      style={{ padding: 20, cursor: onClick ? 'pointer' : undefined, ...style }}
      onClick={onClick}
    >
      {children}
    </div>
  );
}
