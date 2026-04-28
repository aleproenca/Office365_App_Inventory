# Microsoft 365 & Defender App Inventory Tools

Este repositório contém um conjunto de scripts em PowerShell projetados para fornecer visibilidade total sobre o ecossistema de aplicações em ambientes Microsoft 365, integrando dados do **Microsoft Intune**, **Entra ID** e **Microsoft Defender for Endpoint**.

## 🚀 Scripts Incluídos

### 1. Inventário de Aplicações (Intune + Entra ID + Defender)
**Arquivo:** `inventario_aplicacoes.ps1`
Este script realiza uma varredura profunda para identificar aplicações instaladas em dispositivos gerenciados, correlacionando-as com dados ricos de usuários.
- **Diferencial:** Possui uma lógica de "Resolução Robusta de Usuário" que tenta identificar o proprietário do dispositivo através de 4 fontes diferentes (Intune UPN, Intune UserId, Entra Device Mapping e logs do Defender).
- **Saída:** Gera relatórios em `.csv` e `.xlsx` com codificação UTF-8 BOM (compatível com acentuação no Excel PT-BR).

### 2. Inventário de Web Apps/Cloud (Defender Advanced Hunting)
**Arquivo:** `inventario_webapps_defender.ps1`
Focado em Schatten-IT (Shadow IT) e uso de nuvem, este script extrai acessos a aplicações Web e Cloud diretamente dos eventos de rede do Defender.
- **Diferencial:** Implementa um sistema de *fallback* automático entre as APIs `api.security.microsoft.com` (M365 Defender) e `api.securitycenter.microsoft.com` (WindowsDefenderATP).
- **Funcionalidade:** Analisa janelas de tempo personalizáveis (ex: últimos 30 dias) e filtra domínios internos para focar em acessos externos relevantes.

## 🛠️ Pré-requisitos & Configuração

### Registro de Aplicativo (Azure AD / Entra ID)
Para que os scripts funcionem, você deve criar um **App Registration** no portal do Azure e conceder as seguintes permissões de API do tipo **Suporte de Aplicativo (Application)**:

| API | Permissão | Justificativa |
| :--- | :--- | :--- |
| **Microsoft Graph** | `DeviceManagementManagedDevices.Read.All` | Coleta dados de dispositivos no Intune. |
| **Microsoft Graph** | `User.Read.All` | Coleta detalhes de usuários (Departamento, Cargo, etc). |
| **Microsoft Graph** | `Device.Read.All` | Mapeamento de Primary User e Registered Owners. |
| **WindowsDefenderATP** | `AdvancedQuery.Read.All` | Execução de consultas KQL no Advanced Hunting. |
| **Microsoft Threat Protection** | `AdvancedHunting.Read.All` | Acesso aos eventos de CloudAppEvents e NetworkEvents. |

### Configuração dos Scripts
No início de cada arquivo `.ps1`, preencha as variáveis de autenticação:
```powershell
$TenantId     = "seu-tenant-id"
$ClientId     = "seu-client-id"
$ClientSecret = "seu-client-secret"
