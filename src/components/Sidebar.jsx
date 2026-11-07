import {
  ShieldCheck,
  LayoutDashboard,
  ScanSearch,
  ShieldAlert,
  History,
  ChartNoAxesCombined,
  Settings,
  UserRound,
} from 'lucide-react'

const menuItems = [
  { name: 'Dashboard', icon: LayoutDashboard },
  { name: 'Website Scanner', icon: ScanSearch },
  { name: 'Threat Intelligence', icon: ShieldAlert },
  { name: 'Scan History', icon: History },
  { name: 'Analytics', icon: ChartNoAxesCombined },
  { name: 'Profile', icon: UserRound },
]

function Sidebar() {
  return (
    <aside className="nexvolt-sidebar w-64 min-h-screen bg-[#0d1220] border-r border-white/10 p-5">
      <div className="nexvolt-brand flex items-center gap-3 mb-10">
        <div className="bg-indigo-600 p-2 rounded-xl">
          <ShieldCheck size={25} />
        </div>
        <div>
          <h1 className="text-xl font-bold tracking-wider">NEXVOLT</h1>
          <p className="text-xs text-gray-400">Web Trust Intelligence</p>
        </div>
      </div>

      <p className="nexvolt-menu-label text-xs text-gray-500 uppercase mb-4">
        Main Menu
      </p>

      <nav className="nexvolt-nav space-y-2" aria-label="Main menu">
        {menuItems.map((item, index) => {
          const Icon = item.icon

          return (
            <button
              key={item.name}
              type="button"
              className={`w-full flex items-center gap-3 p-3 rounded-lg text-sm transition ${
                index === 0
                  ? 'bg-indigo-600 text-white'
                  : 'text-gray-400 hover:bg-white/5 hover:text-white'
              }`}
            >
              <Icon size={19} aria-hidden="true" />
              {item.name}
            </button>
          )
        })}
      </nav>

      <div className="nexvolt-settings mt-12 border-t border-white/10 pt-5">
        <button
          type="button"
          className="flex items-center gap-3 text-gray-400 p-3"
        >
          <Settings size={19} aria-hidden="true" />
          Settings
        </button>
      </div>
    </aside>
  )
}

export default Sidebar
