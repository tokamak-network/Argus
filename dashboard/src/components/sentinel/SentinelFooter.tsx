export default function SentinelFooter() {
  return (
    <footer className="mt-auto py-8 border-t border-sentinel-border text-center">
      <p className="text-slate-500 text-sm font-medium">
        Powered by <span className="text-slate-300">Argus</span> - Ethereum Attack Detection &amp; Real-time Forensics
      </p>
      <div className="mt-2 flex justify-center gap-6">
        <a className="text-xs text-sentinel-primary hover:underline" href="#">
          API Documentation
        </a>
        <a className="text-xs text-sentinel-primary hover:underline" href="#">
          System Status
        </a>
        <a className="text-xs text-sentinel-primary hover:underline" href="#">
          Support Desk
        </a>
      </div>
    </footer>
  );
}
