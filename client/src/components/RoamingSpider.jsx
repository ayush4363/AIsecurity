import React, { useState, useEffect, useRef } from 'react';

export default function RoamingSpider() {
  const [position, setPosition] = useState({ x: 0, y: 0 });
  const [angle, setAngle] = useState(0);
  const [isMoving, setIsMoving] = useState(false);
  const [isScampering, setIsScampering] = useState(false);
  const [isWebHanging, setIsWebHanging] = useState(false);
  const [webLength, setWebLength] = useState(0);

  const stateRef = useRef({
    x: 0,
    y: 0,
    targetX: 0,
    targetY: 0,
    speed: 1.4,
    angle: 0,
    targetAngle: 0,
    state: 'CRAWLING', // 'CRAWLING' | 'PAUSED' | 'SCAMPERING' | 'WEB'
    pauseTimer: 0,
    stateDuration: 140,
    mouseX: -9999,
    mouseY: -9999,
    initialized: false,
  });

  // Track cursor position
  useEffect(() => {
    const handleMouseMove = (e) => {
      stateRef.current.mouseX = e.clientX;
      stateRef.current.mouseY = e.clientY;
    };

    window.addEventListener('mousemove', handleMouseMove, { passive: true });
    return () => window.removeEventListener('mousemove', handleMouseMove);
  }, []);

  // Main animation loop centered around the mascot
  useEffect(() => {
    let animId;

    // Helper: Get Mascot / Center coordinates
    const getCenterZone = () => {
      // Find the mascot canvas or hero container if available
      const canvasEl = document.querySelector('canvas');
      if (canvasEl) {
        const rect = canvasEl.getBoundingClientRect();
        return {
          cx: rect.left + rect.width / 2,
          cy: rect.top + rect.height / 2,
        };
      }
      return {
        cx: window.innerWidth * 0.50,
        cy: Math.min(380, window.innerHeight * 0.40),
      };
    };

    // Pick a new target waypoint around the mascot center
    const pickNewTarget = () => {
      const { cx, cy } = getCenterZone();
      const s = stateRef.current;

      // 85% of waypoints are in orbit around the mascot character (radius 130px to 310px)
      const nearMascot = Math.random() < 0.85;

      if (nearMascot) {
        // Pick an angle around the mascot
        const orbitAngle = Math.random() * Math.PI * 2;
        // Radius between 140px and 290px from mascot center
        const radius = 140 + Math.random() * 150;
        
        s.targetX = Math.max(60, Math.min(window.innerWidth - 80, cx + Math.cos(orbitAngle) * radius));
        s.targetY = Math.max(60, Math.min(window.innerHeight - 80, cy + Math.sin(orbitAngle) * radius));
      } else {
        // 15% chance to wander slightly further out towards the floating badges
        const angle = Math.random() * Math.PI * 2;
        const radius = 280 + Math.random() * 120;
        s.targetX = Math.max(60, Math.min(window.innerWidth - 80, cx + Math.cos(angle) * radius));
        s.targetY = Math.max(60, Math.min(window.innerHeight - 80, cy + Math.sin(angle) * radius));
      }
    };

    // Initialize spider near the mascot
    if (!stateRef.current.initialized) {
      const { cx, cy } = getCenterZone();
      const startAngle = Math.random() * Math.PI * 2;
      const startRadius = 180 + Math.random() * 80;
      stateRef.current.x = cx + Math.cos(startAngle) * startRadius;
      stateRef.current.y = cy + Math.sin(startAngle) * startRadius;
      stateRef.current.initialized = true;
      pickNewTarget();
    }

    const loop = () => {
      const s = stateRef.current;
      const { cx, cy } = getCenterZone();

      const dx = s.targetX - s.x;
      const dy = s.targetY - s.y;
      const distToTarget = Math.hypot(dx, dy);

      // Check distance to mouse
      const mdx = s.x - s.mouseX;
      const mdy = s.y - s.mouseY;
      const distToMouse = Math.hypot(mdx, mdy);

      // 1. Cursor avoidance: if mouse is within 125px, scamper around the mascot!
      if (distToMouse < 125 && s.state !== 'WEB') {
        s.state = 'SCAMPERING';
        s.speed = 4.2; // Quick scamper burst
        const escapeAngle = Math.atan2(mdy, mdx);
        const escapeDist = 160;
        s.targetX = Math.max(60, Math.min(window.innerWidth - 80, s.x + Math.cos(escapeAngle) * escapeDist));
        s.targetY = Math.max(60, Math.min(window.innerHeight - 80, s.y + Math.sin(escapeAngle) * escapeDist));
        s.targetAngle = escapeAngle * (180 / Math.PI) + 90;
      }

      // 2. State handling
      if (s.state === 'PAUSED') {
        s.pauseTimer--;
        if (s.pauseTimer <= 0) {
          // If above the mascot, 30% chance to drop down on a silk web thread!
          if (s.y < cy - 60 && Math.abs(s.x - cx) < 260 && Math.random() < 0.30) {
            s.state = 'WEB';
            s.stateDuration = 200;
          } else {
            s.state = 'CRAWLING';
            s.speed = 1.3 + Math.random() * 0.9;
            pickNewTarget();
          }
        }
      } else if (s.state === 'WEB') {
        // Drop down on silk web thread right near mascot
        s.stateDuration--;
        const dropProgress = Math.sin((1 - s.stateDuration / 200) * Math.PI);
        const webDepth = dropProgress * 150;
        setWebLength(webDepth);
        setIsWebHanging(true);

        if (s.stateDuration <= 0) {
          setIsWebHanging(false);
          setWebLength(0);
          s.state = 'CRAWLING';
          s.speed = 1.5;
          pickNewTarget();
        }
      } else {
        // CRAWLING or SCAMPERING
        if (distToTarget < 18) {
          // Reached waypoint -> pause briefly
          s.state = 'PAUSED';
          s.pauseTimer = Math.floor(40 + Math.random() * 85); // 0.7 - 2.1s pause
        } else {
          // Move towards target
          const moveAngle = Math.atan2(dy, dx);
          s.targetAngle = moveAngle * (180 / Math.PI) + 90;

          // Smooth rotation to face travel heading
          let diff = (s.targetAngle - s.angle) % 360;
          if (diff < -180) diff += 360;
          if (diff > 180) diff -= 360;
          s.angle += diff * 0.14;

          s.x += Math.cos(moveAngle) * s.speed;
          s.y += Math.sin(moveAngle) * s.speed;

          // Stay within safe bounds
          s.x = Math.max(50, Math.min(window.innerWidth - 80, s.x));
          s.y = Math.max(50, Math.min(window.innerHeight - 80, s.y));
        }
      }

      setPosition({ x: s.x, y: s.y });
      setAngle(s.angle);
      setIsMoving(s.state === 'CRAWLING' || s.state === 'SCAMPERING');
      setIsScampering(s.state === 'SCAMPERING');

      animId = requestAnimationFrame(loop);
    };

    animId = requestAnimationFrame(loop);
    return () => cancelAnimationFrame(animId);
  }, []);

  // Click to scamper
  const handleClick = () => {
    const s = stateRef.current;
    s.state = 'SCAMPERING';
    s.speed = 4.8;
    const randomAngle = Math.random() * Math.PI * 2;
    s.targetX = Math.max(60, Math.min(window.innerWidth - 80, s.x + Math.cos(randomAngle) * 240));
    s.targetY = Math.max(60, Math.min(window.innerHeight - 80, s.y + Math.sin(randomAngle) * 240));
  };

  return (
    <div className="fixed inset-0 pointer-events-none z-30 overflow-hidden">
      {/* Spider Web Silk Thread when hanging */}
      {isWebHanging && webLength > 5 && (
        <div
          className="absolute w-[1px] bg-white/25"
          style={{
            left: `${position.x + 38}px`,
            top: 0,
            height: `${position.y + webLength}px`,
            transition: 'height 0.05s linear',
          }}
        />
      )}

      {/* 
        BIG ROAMING SPIDER (Centered around the Mascot Character)
        Natural dark shadow with ZERO glowing effects
      */}
      <div
        onClick={handleClick}
        className={`absolute cursor-pointer select-none pointer-events-auto transition-transform ${
          isMoving ? 'animate-spider-crawl' : ''
        }`}
        style={{
          left: `${position.x}px`,
          top: `${position.y + (isWebHanging ? webLength : 0)}px`,
          transform: `rotate(${angle}deg)`,
          width: '78px',
          height: '88px',
          filter: 'drop-shadow(0 4px 8px rgba(0,0,0,0.65))',
        }}
        title="Butler's Pet Spider! Roams around the mascot. Click or move cursor close to see him scamper!"
      >
        <img
          src="/spider.png"
          alt="Roaming Butler Spider"
          className="w-full h-full object-contain"
          draggable={false}
        />
      </div>
    </div>
  );
}
