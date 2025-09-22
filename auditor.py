# auditor.py
import subprocess
import sys
import json
import os

def run_slither(contract_path):
    """
    Executa o Slither contra um contrato e retorna o resultado em JSON.
    Lida com o fato de que o Slither pode retornar um código de erro mesmo quando bem-sucedido (se encontrar vulnerabilidades).
    """
    print(f"[*] Iniciando análise com Slither para: {contract_path}")
    
    if not os.path.exists(contract_path):
        print(f"[!] ERRO: Arquivo não encontrado: {contract_path}")
        return None

    command = [
        "slither",
        contract_path,
        "--solc-solcs-select", "0.5.0",
        "--json", "-"
    ]
    
    try:
        command_str = " ".join(command)
        
        # Executa o comando sem 'check=True' para capturar a saída mesmo em caso de "erro" do Slither
        result = subprocess.run(
            command_str,
            capture_output=True,
            text=True,
            shell=True
        )
        
        # A principal lógica de verificação: se houver saída no stdout, tentamos processá-la como JSON.
        # Isso funciona porque o Slither envia o JSON para stdout mesmo quando encontra problemas.
        if result.stdout:
            try:
                slither_output = json.loads(result.stdout)
                return slither_output
            except json.JSONDecodeError:
                print("[!] Erro: A saída do Slither não foi um JSON válido.")
                print(f"--- Saída recebida do Slither ---\n{result.stdout}")
                return None
        
        # Se chegamos aqui, não houve stdout, então foi um erro real.
        print(f"[!] O Slither terminou com o código de erro {result.returncode} e sem saída JSON.")
        if result.stderr:
            print(f"--- Saída de erro (stderr) ---\n{result.stderr}")
        return None

    except FileNotFoundError:
        print("[!] Erro: O comando 'slither' não foi encontrado. Verifique se o ambiente virtual (venv) está ativo.")
        return None
    except Exception as e:
        print(f"[!] Ocorreu um erro inesperado: {e}")
        return None

def analyze_results(slither_data):
    """
    Analisa o JSON retornado pelo Slither e exibe um relatório amigável.
    """
    if not slither_data or not slither_data.get('success'):
        print("[!] Análise do Slither falhou ou não retornou resultados válidos.")
        if slither_data:
            print(f"--- Dados brutos recebidos ---\n{json.dumps(slither_data, indent=2)}")
        return

    print("\n" + "="*60)
    print("     RELATÓRIO DE AUDITORIA DE SMART CONTRACT")
    print("="*60)

    results = slither_data.get('results', {})
    detectors = results.get('detectors', [])

    if not detectors:
        print("\n\033[92m[✓] Nenhuma vulnerabilidade encontrada pelo Slither! Parabéns.\033[0m")
    else:
        print(f"\n\033[91m[!] Encontradas {len(detectors)} potenciais vulnerabilidades.\033[0m\n")
        
        impact_order = {'High': 3, 'Medium': 2, 'Low': 1, 'Informational': 0}
        detectors.sort(key=lambda x: impact_order.get(x.get('impact', 'Informational'), 0), reverse=True)
        
        for detector in detectors:
            check = detector.get('check', 'N/A')
            impact = detector.get('impact', 'N/A')
            description = detector.get('description', 'N/A').strip()

            color = "\033[91m"
            if impact == 'Medium':
                color = "\033[93m"
            elif impact == 'Low':
                color = "\033[94m"
            elif impact == 'Informational':
                color = "\033[90m"

            print(f"{color}IMPACTO: {impact.upper()}\033[0m")
            print(f"  Detector: {check}")
            print(f"  Descrição: {description}")
            print("-" * 40)
    
    print("\n" + "="*60)

if __name__ == "__main__":
    contract_to_analyze = "contracts/Vulnerable.sol"
    
    slither_data = run_slither(contract_to_analyze)
    
    if slither_data:
        analyze_results(slither_data)