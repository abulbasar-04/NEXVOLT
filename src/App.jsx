import Sidebar from "./components/Sidebar";
import Dashboard from "./pages/Dashboard";

function App() {
  return (
    <div className="nexvolt-shell flex min-h-screen bg-[#080b14] text-white">
      <Sidebar />

      <main className="flex-1 min-w-0">
        <Dashboard />
      </main>
    </div>
  );
}

export default App;
    


        
      