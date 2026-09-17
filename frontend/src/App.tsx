import { HashRouter, Routes, Route } from 'react-router-dom';
import { Layout } from './components/Layout';
import { Lookup } from './pages/Lookup';
import { History } from './pages/History';

function App() {
  return (
    <HashRouter>
      <Routes>
        <Route path="/" element={<Layout><Lookup /></Layout>} />
        <Route path="/history" element={<Layout><History /></Layout>} />
      </Routes>
    </HashRouter>
  );
}

export default App;
