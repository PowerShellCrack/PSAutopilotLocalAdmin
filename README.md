# PSAutopilotLocalAdmin

PowerShell scripts to create local admin during Autopilot enrollment

## Available

There are a few scripts current available; I am working on more...

Script | Status| Explanation | Security | Comments
--|--|--|--|--
AddLocalAdminSimple.ps1 | Tested | Adds administrator account with clear text password to Window Device using Intune | Unsecure | recommended for testing ONLY! |
AddLocalAdminObfuscated.ps1 | Tested | Adds administrator account with obfuscated password to Window Device using Intune | less secure | Could decrypt password if AES key is retrieved |
AddLocalAdminKeyVault.ps1 | Tested | Adds administrator account with random password to Window Device using Intune and stores it in Azure Key Vault using a service principal account | More Secure | Can't retrieve password, but could generate new password using Service Principal Id info. Must be an admin to apply password though
AddLocalAdminFunctionApp.ps1 | Not Available | Adds administrator account with random password to Window Device using a Function app and stores it in Azure Vault | Most Secure | Can't retrieve password, but could generate new password using Function app key info. Must be an admin to apply password though

# DISCLAIMER

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
