import { useEffect, useState, useRef } from "react";

/**
 * Animated circular SVG gauge showing overall security score (0-100).
 * Uses CSS transitions for smooth value updates.
 */
function SecurityScoreGauge({ score = 0, size = 180 }) {
  const [displayScore, setDisplayScore] = useState(0);
  const animRef = useRef(null);

  useEffect(() => {
    const duration = 1200;
    const startTime = performance.now();

    function animate(time) {
      const elapsed = time - startTime;
      const progress = Math.min(elapsed / duration, 1);
      // Ease out cubic
      const eased = 1 - Math.pow(1 - progress, 3);
      setDisplayScore(Math.round(eased * score));
      if (progress < 1) {
        animRef.current = requestAnimationFrame(animate);
      }
    }

    animRef.current = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(animRef.current);
  }, [score]);

  const radius = (size - 20) / 2;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (displayScore / 100) * circumference;

  // Color based on score
  let color = "#ef4444"; // red
  let glowColor = "rgba(239, 68, 68, 0.3)";
  let label = "Critical";
  if (score >= 80) {
    color = "#22c55e";
    glowColor = "rgba(34, 197, 94, 0.3)";
    label = "Excellent";
  } else if (score >= 60) {
    color = "#eab308";
    glowColor = "rgba(234, 179, 8, 0.3)";
    label = "Fair";
  } else if (score >= 40) {
    color = "#f97316";
    glowColor = "rgba(249, 115, 22, 0.3)";
    label = "Poor";
  }

  return (
    <div className="flex flex-col items-center gap-2">
      <svg
        width={size}
        height={size}
        viewBox={`0 0 ${size} ${size}`}
        className="drop-shadow-lg"
        style={{ filter: `drop-shadow(0 0 12px ${glowColor})` }}
      >
        {/* Background circle */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="rgba(51, 65, 85, 0.5)"
          strokeWidth="10"
        />
        {/* Progress arc */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
          style={{ transition: "stroke-dashoffset 0.3s ease-out" }}
        />
        {/* Score text */}
        <text
          x={size / 2}
          y={size / 2 - 8}
          textAnchor="middle"
          dominantBaseline="central"
          className="fill-white text-4xl font-bold"
          style={{ fontSize: "2.25rem", fontFamily: "Inter, sans-serif", fontWeight: 800 }}
        >
          {displayScore}
        </text>
        <text
          x={size / 2}
          y={size / 2 + 22}
          textAnchor="middle"
          dominantBaseline="central"
          className="fill-slate-400"
          style={{ fontSize: "0.7rem", fontFamily: "Inter, sans-serif", fontWeight: 500, letterSpacing: "0.1em", textTransform: "uppercase" }}
        >
          / 100
        </text>
      </svg>
      <div className="text-center">
        <span
          className="text-xs font-bold uppercase tracking-widest px-3 py-1 rounded-full"
          style={{
            color,
            background: `${color}15`,
            border: `1px solid ${color}30`
          }}
        >
          {label}
        </span>
      </div>
    </div>
  );
}

export default SecurityScoreGauge;
