import { useEffect, useRef } from "react";
import * as THREE from "three";
import type { GraphData } from "../data/geo";

// Concrete hex for the WebGL canvas.
const HEX: Record<string, number> = {
  critical: 0xef4444,
  high: 0xf97316,
  medium: 0xfacc15,
  low: 0x22c55e,
  info: 0x9ca3af,
};

interface Sim {
  id: string;
  pos: THREE.Vector3;
  vel: THREE.Vector3;
  val: number;
  color: number;
  hot: boolean;
}

// Self-contained three.js force graph. Avoids react-force-graph (which
// bundles a second React copy and breaks in the preview sandbox). Small
// node counts (≤40) — a few relaxation iterations + slow auto-rotate.
export default function ForceGraph3DInner({ data }: { data: GraphData }) {
  const mount = useRef<HTMLDivElement>(null);
  const dataRef = useRef(data);
  dataRef.current = data;

  useEffect(() => {
    const el = mount.current;
    if (!el) return;

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(60, 1, 0.1, 2000);
    camera.position.z = 320;

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setClearColor(0x000000, 0);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    el.appendChild(renderer.domElement);

    const group = new THREE.Group();
    scene.add(group);
    scene.add(new THREE.AmbientLight(0xffffff, 0.9));
    const point = new THREE.PointLight(0xffffff, 0.6);
    point.position.set(200, 200, 200);
    scene.add(point);

    let nodes: Sim[] = [];
    let nodeMeshes: THREE.Mesh[] = [];
    let linkGeom: THREE.BufferGeometry | null = null;
    let linkLine: THREE.LineSegments | null = null;
    let links: { s: Sim; t: Sim; color: number }[] = [];
    let signature = "";

    const rebuild = () => {
      const d = dataRef.current;
      const sig = `${d.nodes.map((n) => n.id + n.val + n.severity).join()}|${d.links.length}`;
      if (sig === signature) return;
      signature = sig;

      const prev = new Map(nodes.map((n) => [n.id, n.pos]));
      nodeMeshes.forEach((m) => {
        group.remove(m);
        m.geometry.dispose();
        (m.material as THREE.Material).dispose();
      });
      if (linkLine) {
        group.remove(linkLine);
        linkGeom?.dispose();
      }

      nodes = d.nodes.map((n) => {
        const p =
          prev.get(n.id) ??
          new THREE.Vector3(
            (Math.random() - 0.5) * 180,
            (Math.random() - 0.5) * 180,
            (Math.random() - 0.5) * 180,
          );
        return {
          id: n.id,
          pos: p.clone(),
          vel: new THREE.Vector3(),
          val: n.val,
          color: n.kind === "domain" ? 0xffffff : HEX[n.severity],
          hot: n.hot,
        };
      });
      const byId = new Map(nodes.map((n) => [n.id, n]));

      links = d.links
        .map((l) => {
          const s = byId.get(typeof l.source === "string" ? l.source : (l.source as any).id);
          const t = byId.get(typeof l.target === "string" ? l.target : (l.target as any).id);
          return s && t ? { s, t, color: HEX[l.severity] } : null;
        })
        .filter(Boolean) as { s: Sim; t: Sim; color: number }[];

      // relax layout
      for (let iter = 0; iter < 120; iter++) {
        for (let i = 0; i < nodes.length; i++) {
          for (let j = i + 1; j < nodes.length; j++) {
            const a = nodes[i].pos;
            const b = nodes[j].pos;
            const d3 = a.clone().sub(b);
            const dist = Math.max(8, d3.length());
            const f = 900 / (dist * dist);
            d3.normalize().multiplyScalar(f);
            nodes[i].vel.add(d3);
            nodes[j].vel.sub(d3);
          }
        }
        for (const l of links) {
          const d3 = l.t.pos.clone().sub(l.s.pos);
          const dist = d3.length();
          const f = (dist - 70) * 0.02;
          d3.normalize().multiplyScalar(f);
          l.s.vel.add(d3);
          l.t.vel.sub(d3);
        }
        for (const n of nodes) {
          n.pos.add(n.vel.clone().multiplyScalar(0.85));
          n.pos.multiplyScalar(0.995); // gentle centering
          n.vel.multiplyScalar(0.6);
        }
      }

      nodeMeshes = nodes.map((n) => {
        const r = 2.6 + Math.min(6, n.val * 0.7);
        const geo = new THREE.SphereGeometry(r, 16, 16);
        const mat = new THREE.MeshStandardMaterial({
          color: n.color,
          emissive: n.color,
          emissiveIntensity: n.hot ? 0.9 : 0.35,
          roughness: 0.4,
        });
        const mesh = new THREE.Mesh(geo, mat);
        mesh.position.copy(n.pos);
        group.add(mesh);
        return mesh;
      });

      const positions = new Float32Array(links.length * 6);
      const colors = new Float32Array(links.length * 6);
      links.forEach((l, i) => {
        positions.set([l.s.pos.x, l.s.pos.y, l.s.pos.z, l.t.pos.x, l.t.pos.y, l.t.pos.z], i * 6);
        const c = new THREE.Color(l.color);
        colors.set([c.r, c.g, c.b, c.r, c.g, c.b], i * 6);
      });
      linkGeom = new THREE.BufferGeometry();
      linkGeom.setAttribute("position", new THREE.BufferAttribute(positions, 3));
      linkGeom.setAttribute("color", new THREE.BufferAttribute(colors, 3));
      linkLine = new THREE.LineSegments(
        linkGeom,
        new THREE.LineBasicMaterial({ vertexColors: true, transparent: true, opacity: 0.35 }),
      );
      group.add(linkLine);
    };

    const resize = () => {
      const w = el.clientWidth || 1;
      const h = el.clientHeight || 1;
      renderer.setSize(w, h, false);
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
    };
    const ro = new ResizeObserver(resize);
    ro.observe(el);
    resize();

    let raf = 0;
    let t = 0;
    const loop = () => {
      raf = requestAnimationFrame(loop);
      rebuild();
      t += 0.0025;
      group.rotation.y += 0.0018;
      group.rotation.x = Math.sin(t) * 0.12;
      // pulse hot nodes
      nodeMeshes.forEach((m, i) => {
        if (nodes[i]?.hot) {
          const s = 1 + Math.sin(t * 12) * 0.18;
          m.scale.setScalar(s);
        }
      });
      renderer.render(scene, camera);
    };
    loop();

    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
      nodeMeshes.forEach((m) => {
        m.geometry.dispose();
        (m.material as THREE.Material).dispose();
      });
      linkGeom?.dispose();
      renderer.dispose();
      if (renderer.domElement.parentNode === el) el.removeChild(renderer.domElement);
    };
  }, []);

  return <div ref={mount} className="absolute inset-0" />;
}
