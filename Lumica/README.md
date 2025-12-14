# School App

## Overview
The School App is a comprehensive platform designed to facilitate the management of student information, results, and communication between students, teachers, and administrators. It provides a user-friendly interface for students to access their results, while enabling teachers and administrators to manage student data efficiently.

## Features

### Student Portal
- **Login**: Students can log in using their admission number and surname.
- **View Results**: Students can view their academic results.
- **Download Results**: Students have the option to download their results in PDF format.

### Teacher Dashboard
- **Generate Results**: Teachers can generate results for their classes.
- **Send Results**: Teachers can choose to send results directly to the student portal or download them for offline use.
- **Prompt for Admission Number**: When sending results to the portal, teachers will be prompted to enter the student's admission number.

### Admin Dashboard
- **Add Students**: Admins can add new students through a dedicated interface.
- **Manage Users**: Admins can manage student and teacher accounts.

## Technologies Used
- **Backend**: Node.js, Express, TypeScript
- **Frontend**: React, TypeScript
- **Database**: [Database technology used, e.g., MongoDB, PostgreSQL]
- **PDF Generation**: Utilizes a utility for generating PDF documents of student results.

## Setup Instructions
1. Clone the repository:
   ```
   git clone https://github.com/bamidelestephen234-pixel/Lumica.git
   ```
2. Navigate to the server directory and install dependencies:
   ```
   cd Lumica/server
   npm install
   ```
3. Navigate to the client directory and install dependencies:
   ```
   cd ../client
   npm install
   ```
4. Run database migrations and seed the database:
   ```
   cd ../db
   ts-node seed.ts
   ```
5. Start the server:
   ```
   cd ../server
   npm start
   ```
6. Start the client:
   ```
   cd ../client
   npm start
   ```

## Contributing
Contributions are welcome! Please open an issue or submit a pull request for any enhancements or bug fixes.

## License
This project is licensed under the MIT License. See the LICENSE file for details.