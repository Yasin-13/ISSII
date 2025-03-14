import React, { useEffect, useState } from "react";
import axios from "axios";

const Dashboard = () => {
  const [reports, setReports] = useState([]);

  useEffect(() => {
    axios.get("http://127.0.0.1:5000/audit/reports")
      .then(response => setReports(response.data))
      .catch(error => console.error("Error fetching audit reports:", error));
  }, []);

  return (
    <div className="p-6 bg-gray-100 min-h-screen">
      <h1 className="text-2xl font-bold mb-4">Security Audit Reports</h1>
      <table className="min-w-full bg-white border border-gray-300">
        <thead>
          <tr>
            <th className="px-4 py-2">Category</th>
            <th className="px-4 py-2">Details</th>
            <th className="px-4 py-2">Timestamp</th>
          </tr>
        </thead>
        <tbody>
          {reports.map((report) => (
            <tr key={report._id}>
              <td className="border px-4 py-2">{report.category}</td>
              <td className="border px-4 py-2">{report.details}</td>
              <td className="border px-4 py-2">{report.timestamp}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default Dashboard;
