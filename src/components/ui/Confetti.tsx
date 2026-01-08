import { useEffect, useState } from 'react';

interface ConfettiPiece {
  id: number;
  x: number;
  delay: number;
  color: string;
  size: number;
  rotation: number;
}

interface ConfettiProps {
  isActive: boolean;
  duration?: number;
}

const colors = [
  'hsl(187 80% 55%)', // primary cyan
  'hsl(142 76% 42%)', // green
  'hsl(45 93% 52%)',  // yellow
  'hsl(280 70% 55%)', // purple
  'hsl(210 80% 55%)', // blue
  'hsl(25 95% 58%)',  // orange
];

export function Confetti({ isActive, duration = 3000 }: ConfettiProps) {
  const [pieces, setPieces] = useState<ConfettiPiece[]>([]);
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    if (isActive) {
      // Generate confetti pieces
      const newPieces: ConfettiPiece[] = Array.from({ length: 50 }, (_, i) => ({
        id: i,
        x: Math.random() * 100,
        delay: Math.random() * 0.5,
        color: colors[Math.floor(Math.random() * colors.length)],
        size: Math.random() * 8 + 4,
        rotation: Math.random() * 360,
      }));
      setPieces(newPieces);
      setIsVisible(true);

      // Clean up after duration
      const timeout = setTimeout(() => {
        setIsVisible(false);
        setTimeout(() => setPieces([]), 500);
      }, duration);

      return () => clearTimeout(timeout);
    }
  }, [isActive, duration]);

  if (!pieces.length) return null;

  return (
    <div 
      className={`fixed inset-0 pointer-events-none z-50 overflow-hidden transition-opacity duration-500 ${
        isVisible ? 'opacity-100' : 'opacity-0'
      }`}
    >
      {pieces.map((piece) => (
        <div
          key={piece.id}
          className="absolute animate-confetti-fall"
          style={{
            left: `${piece.x}%`,
            top: '-20px',
            width: `${piece.size}px`,
            height: `${piece.size * 0.6}px`,
            backgroundColor: piece.color,
            borderRadius: '2px',
            animationDelay: `${piece.delay}s`,
            transform: `rotate(${piece.rotation}deg)`,
            animationDuration: `${2 + Math.random()}s`,
          }}
        />
      ))}
    </div>
  );
}
