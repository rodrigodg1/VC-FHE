import pandas as pd

# Load the experiment results from CSV
# This file contains performance metrics for different dataset sizes
df = pd.read_csv("experiment_results.csv")

# ==========================================
# 1. SETUP PHASE
# Calculate overall mean and standard deviation for the setup time 
# (measured in milliseconds) across all experiments.
# ==========================================

def show_setup():   
    print("\n ########### Setup  ###########\n")

    mean = df['setup_ms'].mean()
    std = df['setup_ms'].std()

    print(f"Mean: {mean} ms")
    print(f"Std: {std} ms")



def show_encryption_signing_on_chain_commit():
        
    # ==========================================
    # 2. ENCRYPTION & SIGNING
    # Calculate mean and standard deviation for encryption and signing time 
    # (measured in milliseconds), grouped by the dataset size (n = 10, 50, 100, 200).
    # ==========================================
    print("\n ########### Encryption & Signing ########### \n")

    print("n=10")
    df_10 = df[df['dataset_size'] == 10]
    print(f"Mean: {df_10['encrypt_sign_ms'].mean()} ms")
    print(f"Std: {df_10['encrypt_sign_ms'].std()} ms\n")

    print("n=50")
    df_50 = df[df['dataset_size'] == 50]
    print(f"Mean: {df_50['encrypt_sign_ms'].mean()} ms")
    print(f"Std: {df_50['encrypt_sign_ms'].std()} ms\n")

    print("n=100")
    df_100 = df[df['dataset_size'] == 100]
    print(f"Mean: {df_100['encrypt_sign_ms'].mean()} ms")
    print(f"Std: {df_100['encrypt_sign_ms'].std()} ms\n")

    print("n=200")
    df_200 = df[df['dataset_size'] == 200]
    print(f"Mean: {df_200['encrypt_sign_ms'].mean()} ms")
    print(f"Std: {df_200['encrypt_sign_ms'].std()} ms\n")

    # ==========================================
    # 3. FHE COMPUTATION AND VERIFICATION
    # Calculate mean and standard deviation for FHE sign aggregation.
    # The column `fhe_sign_aggregation_ms` is in milliseconds, so values
    # are divided by 1000 to be displayed in seconds.
    # Verification transaction time (`verification_tx_s`) is already in seconds.
    # Data is grouped by dataset size (n = 10, 50, 100, 200).
    # ==========================================
    print("\n ########### FHE Computation and Aggregation ########### \n")

    # ---- n = 10 ----
    df_fhe_computation_10 = df[df['dataset_size'] == 10]['fhe_sign_aggregation_ms']
    df_fhe_verification_10 = df[df['dataset_size'] == 10]['verification_tx_s']

    print("n=10\n")
    print("FHE Computation (seconds):")
    print(df_fhe_computation_10.mean()/1000)
    print(df_fhe_computation_10.std()/1000)

    print("Verification (seconds):")
    print(df_fhe_verification_10.mean())
    print(df_fhe_verification_10.std())

    print("\n")

    # ---- n = 50 ----
    print("n=50\n")
    print("FHE Computation (seconds):")
    df_fhe_computation_50 = df[df['dataset_size'] == 50]['fhe_sign_aggregation_ms']
    df_fhe_verification_50 = df[df['dataset_size'] == 50]['verification_tx_s']
    print(df_fhe_computation_50.mean()/1000)
    print(df_fhe_computation_50.std()/1000)

    print("Verification (seconds):")
    print(df_fhe_verification_50.mean())
    print(df_fhe_verification_50.std())

    print("\n")

    # ---- n = 100 ----
    print("n=100\n")
    print("FHE Computation (seconds):")
    df_fhe_computation_100 = df[df['dataset_size'] == 100]['fhe_sign_aggregation_ms']
    df_fhe_verification_100 = df[df['dataset_size'] == 100]['verification_tx_s']
    print(df_fhe_computation_100.mean()/1000)
    print(df_fhe_computation_100.std()/1000)

    print("Verification (seconds):")
    print(df_fhe_verification_100.mean())
    print(df_fhe_verification_100.std())

    print("\n")

    # ---- n = 200 ----
    print("n=200\n")
    print("FHE Computation (seconds):")
    df_fhe_computation_200 = df[df['dataset_size'] == 200]['fhe_sign_aggregation_ms']
    df_fhe_verification_200 = df[df['dataset_size'] == 200]['verification_tx_s']
    print(df_fhe_computation_200.mean()/1000)
    print(df_fhe_computation_200.std()/1000)

    print("Verification (seconds):")
    print(df_fhe_verification_200.mean())
    print(df_fhe_verification_200.std())




def show_verification_routine():

    df_verification_routine_10 = df[df['dataset_size'] == 10]['verification_call_ms']
    df_verification_routine_50 = df[df['dataset_size'] == 50]['verification_call_ms']
    df_verification_routine_100 = df[df['dataset_size'] == 100]['verification_call_ms']
    df_verification_routine_200 = df[df['dataset_size'] == 200]['verification_call_ms']


    print("\n ########### Verification process: RHS reconstruction + BN254 pairing ########### \n")

    print("n=10")
    print(df_verification_routine_10.mean())


    print("n=50")
    print(df_verification_routine_50.mean())


    print("n=100")
    print(df_verification_routine_100.mean())


    print("n=200")
    print(df_verification_routine_200.mean())


def show_cost_deployment_verification():

    df_gas_verification_10 = df[df['dataset_size'] == 10]['gas_used']
    df_gas_verification_50 = df[df['dataset_size'] == 50]['gas_used']
    df_gas_verification_100 = df[df['dataset_size'] == 100]['gas_used']
    df_gas_verification_200 = df[df['dataset_size'] == 200]['gas_used']


    df_deploy = pd.read_csv("deployment_costs.csv")

    df_deployment_cost_10 = df_deploy[df_deploy['dataset_size'] == 10]['deployment_gas_used']
    df_deployment_cost_50 = df_deploy[df_deploy['dataset_size'] == 50]['deployment_gas_used']
    df_deployment_cost_100 = df_deploy[df_deploy['dataset_size'] == 100]['deployment_gas_used']
    df_deployment_cost_200 = df_deploy[df_deploy['dataset_size'] == 200]['deployment_gas_used']

    print("\n ########### Contract Deployment Gas Cost ########### \n")

    print("n=10")
    print(df_deployment_cost_10.mean())

    print("n=50")
    print(df_deployment_cost_50.mean())

    print("n=100")
    print(df_deployment_cost_100.mean())

    print("n=200")
    print(df_deployment_cost_200.mean())


    print("\n ########### Verification Gas Cost ########### \n")

    print("n=10")
    print(df_gas_verification_10.mean())

    print("n=50")
    print(df_gas_verification_50.mean())

    print("n=100")
    print(df_gas_verification_100.mean())

    print("n=200")
    print(df_gas_verification_200.mean())





def show_tx_size():


    df_deploy = pd.read_csv("deployment_costs.csv")
    df_tx_size_10 = df_deploy[df_deploy['dataset_size'] == 10]['deployment_tx_size_bytes']
    df_tx_size_50 = df_deploy[df_deploy['dataset_size'] == 50]['deployment_tx_size_bytes']
    df_tx_size_100 = df_deploy[df_deploy['dataset_size'] == 100]['deployment_tx_size_bytes']
    df_tx_size_200 = df_deploy[df_deploy['dataset_size'] == 200]['deployment_tx_size_bytes']

    print("\n ########### Contract Deployment Tx Size ########### \n")

    print("n=10")
    print(df_tx_size_10.mean())

    print("n=50")
    print(df_tx_size_50.mean())

    print("n=100")
    print(df_tx_size_100.mean())

    print("n=200")
    print(df_tx_size_200.mean())


    print("\n ########### Verification Tx Size ########### \n")

    df_tx_size_verification_10 = df[df['dataset_size'] == 10]['tx_size_bytes']
    df_tx_size_verification_50 = df[df['dataset_size'] == 50]['tx_size_bytes']
    df_tx_size_verification_100 = df[df['dataset_size'] == 100]['tx_size_bytes']
    df_tx_size_verification_200 = df[df['dataset_size'] == 200]['tx_size_bytes']


    print("n=10")
    print(df_tx_size_verification_10.mean())

    print("n=50")
    print(df_tx_size_verification_50.mean())

    print("n=100")
    print(df_tx_size_verification_100.mean())

    print("n=200")
    print(df_tx_size_verification_200.mean())





#show_setup()
#show_encryption_signing_on_chain_commit()
#show_verification_routine()
#show_cost_deployment_verification()
#show_tx_size()


