// From a real codebase: an outbound call to the core banking API, not a route
const disbResponse = await axios.post(`${CBA_BASE_URL}/api/Loan/LoanDisbursement`, payload);
