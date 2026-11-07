import {
  Globe,
  ShieldAlert,
  ShieldCheck,
  Activity,
  Search,
} from 'lucide-react'

const stats = [
  {
    title: 'Websites Scanned',
    value: '1,284',
    icon: Globe,
    color: 'text-blue-400',
  },
  {
    title: 'Threats Detected',
    value: '247',
    icon: ShieldAlert,
    color: 'text-red-400',
  },
  {
    title: 'Safe Websites',
    value: '987',
    icon: ShieldCheck,
    color: 'text-green-400',
  },
  {
    title: 'Active Monitoring',
    value: '24/7',
    icon: Activity,
    color: 'text-purple-400',
  },
]

function Dashboard() {
  return (
    <div className="nexvolt-dashboard-content p-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold">Security Dashboard</h1>
        <p className="text-gray-400 mt-2">
          Welcome to NEXVOLT. Monitor website security and detect online
          threats.
        </p>
      </div>

      <div className="nexvolt-dashboard-stats grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-5">
        {stats.map((item) => {
          const Icon = item.icon

          return (
            <div
              key={item.title}
              className="nexvolt-card bg-[#111827] border border-white/10 rounded-xl p-5"
            >
              <div className="flex justify-between items-center">
                <p className="text-gray-400 text-sm">{item.title}</p>
                <Icon className={item.color} size={23} aria-hidden="true" />
              </div>
              <h2 className="text-3xl font-bold mt-4">{item.value}</h2>
            </div>
          )
        })}
      </div>

      <section className="mt-8 bg-[#111827] border border-white/10 rounded-xl p-6">
        <h2 className="text-xl font-semibold mb-2">Scan a Website</h2>
        <p className="text-gray-400 text-sm mb-5">
          Check websites for phishing and security threats.
        </p>
        <form className="flex flex-col md:flex-row gap-3">
          <label className="sr-only" htmlFor="website-url">
            Website URL
          </label>
          <input
            id="website-url"
            type="url"
            placeholder="Enter website URL..."
            className="flex-1 bg-[#080b14] border border-white/10 rounded-lg px-4 py-3 outline-none focus:border-indigo-500"
          />
          <button
            type="button"
            className="bg-indigo-600 hover:bg-indigo-700 rounded-lg px-6 py-3 font-medium flex items-center justify-center gap-2"
          >
            <Search size={18} aria-hidden="true" />
            Scan Website
          </button>
        </form>
      </section>

      <section className="mt-8 bg-[#111827] border border-white/10 rounded-xl p-6">
        <h2 className="text-xl font-semibold mb-5">Recent Scan Activity</h2>
        <div className="space-y-4">
          <div className="flex justify-between border-b border-white/10 pb-3">
            <span className="text-gray-300">example.com</span>
            <span className="text-green-400">Safe</span>
          </div>
          <div className="flex justify-between border-b border-white/10 pb-3">
            <span className="text-gray-300">suspicious-demo.test</span>
            <span className="text-yellow-400">Suspicious</span>
          </div>
          <div className="flex justify-between">
            <span className="text-gray-300">phishing-demo.test</span>
            <span className="text-red-400">Malicious</span>
          </div>
        </div>
        <p className="text-xs text-gray-500 mt-4">
          Sample demonstration records only.
        </p>
      </section>
    </div>
  )
}

export default Dashboard
