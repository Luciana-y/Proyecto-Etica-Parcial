import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from imblearn.over_sampling import SMOTE
import joblib

# Load the dataset
df = pd.read_csv('./data/diabetic_data_clean.csv')

print(df['readmitted'].value_counts())
print(df['readmitted'].value_counts(normalize=True) * 100)


# Separate features and target variable
X = df.drop('readmitted', axis=1)
y = df['readmitted']

# Identify categorical and numerical columns
numerical_cols = X.select_dtypes(include=np.number).columns
categorical_cols = X.select_dtypes(include='object').columns

# Create a preprocessing pipeline for numerical and categorical features
preprocessor = ColumnTransformer(
    transformers=[
        ('num', StandardScaler(), numerical_cols),
        ('cat', OneHotEncoder(handle_unknown='ignore'), categorical_cols)
    ])

# Split data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

print(f"X_train shape: {X_train.shape}")
print(f"X_test shape: {X_test.shape}")
print(f"y_train shape: {y_train.shape}")
print(f"y_test shape: {y_test.shape}")

# Apply preprocessing to training data first
X_train_processed = preprocessor.fit_transform(X_train)

# Apply SMOTE to the processed training data
smote = SMOTE(random_state=42)
X_train_resampled, y_train_resampled = smote.fit_resample(X_train_processed, y_train)

print("Shape of X_train_resampled after SMOTE:", X_train_resampled.shape)
print("Distribution of y_train_resampled after SMOTE:")
print(pd.Series(y_train_resampled).value_counts())

# Initialize and train the model
model = LogisticRegression(random_state=42, solver='liblinear', class_weight='balanced', max_iter=1000)
model.fit(X_train_resampled, y_train_resampled)

print("Model training complete.")


# Preprocess the test data
X_test_processed = preprocessor.transform(X_test)

# Make predictions
y_pred = model.predict(X_test_processed)
y_prob = model.predict_proba(X_test_processed)[:, 1]

# Evaluate the model
print("Classification Report:")
print(classification_report(y_test, y_pred))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))

print("\nROC AUC Score:", roc_auc_score(y_test, y_prob))


joblib.dump(model, './models/logistic_regression_model.joblib')
joblib.dump(preprocessor, './models/preprocessor.joblib')
joblib.dump(numerical_cols, './models/numerical_cols.joblib')
joblib.dump(categorical_cols, './models/categorical_cols.joblib')

print("Model, preprocessor, numerical and categorical column names saved successfully.")
print("You can load them in your FastAPI application using joblib.load().")

