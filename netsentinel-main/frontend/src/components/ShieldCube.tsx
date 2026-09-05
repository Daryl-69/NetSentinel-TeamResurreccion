import { Shield } from "lucide-react";

// CSS-only rotating 3D cube used as the NetSentinel mark.
export default function ShieldCube() {
  return (
    <div className="cube-scene shrink-0">
      <div className="cube">
        <div className="cube-face cube-face-front">
          <Shield size={15} strokeWidth={1.75} />
        </div>
        <div className="cube-face cube-face-back" />
        <div className="cube-face cube-face-right" />
        <div className="cube-face cube-face-left" />
        <div className="cube-face cube-face-top" />
        <div className="cube-face cube-face-bottom" />
      </div>
    </div>
  );
}
