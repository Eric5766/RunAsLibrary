using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using RunAsLibrary;

namespace TestApp
{
   
    class Program
    {
        static void Main(string[] args)
        {
            Api api = new Api();

            string username = "testuser";
            string password = "1";

            try
            {
                Console.WriteLine("Creating user...");

                // This will create the user, or update the password if the user exists
                api.Create(username, password);

                Console.WriteLine("Running program with full restrictions...");

                SecurityRestrictions fullRestrictions =
                    SecurityRestrictions.DenyProgramFiles |
                    SecurityRestrictions.LowIntegrity |
                    SecurityRestrictions.BasicJobLimits;

                // Replace these paths with your actual program path
                string programDirectory = @"C:\Path\To\Your\Program";
                string programExe = "YourProgram.exe";

                // Below will be the directory on which the new user will be denied all access
                string protectedPath = @"C:\Path\To\Your\Protected\Program";

                api.run_target(
                    programDirectory,         // Directory of program to run
                    programExe,                 // Program to run
                    username,                     // Username
                    password,                  // Password
                    "",                            // Arguments
                    protectedPath, 
                    fullRestrictions
                ); ;

                Console.WriteLine("Program launched successfully!");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }

            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
        }
    }
}
