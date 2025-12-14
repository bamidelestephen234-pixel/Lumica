import { Document, Page, Text, View, StyleSheet, PDFDownloadLink } from '@react-pdf/renderer';

const styles = StyleSheet.create({
  page: {
    flexDirection: 'column',
    padding: 30,
  },
  section: {
    marginBottom: 10,
  },
  title: {
    fontSize: 24,
    marginBottom: 20,
    textAlign: 'center',
  },
  result: {
    fontSize: 18,
    marginBottom: 5,
  },
});

const ResultDocument = ({ studentName, admissionNumber, results }) => (
  <Document>
    <Page size="A4" style={styles.page}>
      <Text style={styles.title}>Student Results</Text>
      <View style={styles.section}>
        <Text style={styles.result}>Name: {studentName}</Text>
        <Text style={styles.result}>Admission Number: {admissionNumber}</Text>
      </View>
      <View style={styles.section}>
        <Text style={styles.result}>Results:</Text>
        {results.map((result, index) => (
          <Text key={index} style={styles.result}>{result}</Text>
        ))}
      </View>
    </Page>
  </Document>
);

export const generatePDF = (studentName, admissionNumber, results) => {
  return (
    <PDFDownloadLink
      document={<ResultDocument studentName={studentName} admissionNumber={admissionNumber} results={results} />}
      fileName={`${admissionNumber}_results.pdf`}
    >
      {({ loading }) => (loading ? 'Loading document...' : 'Download Results')}
    </PDFDownloadLink>
  );
};